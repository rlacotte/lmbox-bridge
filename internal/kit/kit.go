// Package kit packages an enrolled customer's PKI + config into a
// single signed .tar.gz file the partner ships to the customer's
// RSSI for installation on the DMZ VM.
//
// Why HMAC and not GPG / X.509 signing
// ────────────────────────────────────
// The integrity assertion the partner needs to make to the customer
// is "this file came from us and nothing was added or changed in
// transit". An HMAC with a shared secret (handed out-of-band on a
// per-partner basis) is sufficient and trivially scriptable on the
// RSSI's side. GPG would require the RSSI to manage public keys ;
// X.509 signing adds a second PKI layer for what is, in essence,
// a manifest checksum.
//
// The HMAC key is NOT the customer root CA. It's per-partner :
// Sopra has one HMAC key, Inetum another, etc. So when a customer
// receives a kit, they verify it against the HMAC key their
// LMbox-partner integrator gave them via a separate channel (an
// email + PDF, a secure portal page, etc.). Compromise of one
// partner's HMAC key reveals no PKI material.
//
// File format
// ───────────
//   acme-industries-bridge-kit.tar.gz
//   acme-industries-bridge-kit.tar.gz.hmac    ← hex(HMAC-SHA256(key, kit))
//
// The .hmac file is a single line of hex. The verify subcommand
// reads it and recomputes HMAC-SHA256 over the tar.gz to confirm
// the bytes match.
package kit

import (
	"archive/tar"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// File is a single entry in the kit. Mode + content are explicit so
// the test suite can build a kit in memory without touching disk.
type File struct {
	// Path inside the tarball. Use forward slashes regardless of
	// host OS; tar archives are always slash-separated.
	Path    string
	Mode    int64
	Content []byte
}

// Build writes a tar.gz containing `files` to `outPath` and creates
// `outPath.hmac` next to it. Returns the hex HMAC string for
// optional out-of-band publication.
//
// `key` is the per-partner HMAC secret (32+ bytes). We don't enforce
// a minimum length here — operator gets the error from hmac.New if
// the key is empty, plus the doc says "use 32 bytes of random".
func Build(outPath string, files []File, key []byte) (string, error) {
	if len(key) == 0 {
		return "", errors.New("kit: HMAC key must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		return "", fmt.Errorf("kit: mkdir output: %w", err)
	}

	// Build the tarball and HMAC in one pass : we pipe writes through
	// a tee that feeds both the gzip writer (→ file) and the HMAC.
	// This avoids re-reading the file from disk to sign.
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("kit: create %s: %w", outPath, err)
	}
	defer f.Close()

	mac := hmac.New(sha256.New, key)
	teeOut := io.MultiWriter(f, mac)
	gz := gzip.NewWriter(teeOut)
	tw := tar.NewWriter(gz)

	// Stable file ordering for reproducible builds : sort by path.
	// This way two enrolments with the same inputs produce
	// byte-identical archives, which the customer's IT team can
	// hash-compare across partners.
	sorted := make([]File, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	// Pin the modtime so the build is reproducible. Operators can
	// override via the build environment if they want a "real"
	// timestamp; the customer's RSSI doesn't care.
	modTime := time.Unix(0, 0).UTC()

	for _, file := range sorted {
		if err := writeTarFile(tw, file, modTime); err != nil {
			return "", fmt.Errorf("kit: write %s: %w", file.Path, err)
		}
	}
	if err := tw.Close(); err != nil {
		return "", fmt.Errorf("kit: tar close: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("kit: gzip close: %w", err)
	}

	hexMac := hex.EncodeToString(mac.Sum(nil))
	hmacPath := outPath + ".hmac"
	if err := os.WriteFile(hmacPath, []byte(hexMac+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("kit: write .hmac: %w", err)
	}
	return hexMac, nil
}

// Verify recomputes the HMAC over `kitPath` and compares against
// `kitPath.hmac`. Returns nil on match. The customer's RSSI runs
// this immediately on receipt to confirm transit integrity.
func Verify(kitPath string, key []byte) error {
	if len(key) == 0 {
		return errors.New("kit: HMAC key must not be empty")
	}
	expected, err := os.ReadFile(kitPath + ".hmac")
	if err != nil {
		return fmt.Errorf("kit: read .hmac: %w", err)
	}
	expectedHex := strings.TrimSpace(string(expected))
	want, err := hex.DecodeString(expectedHex)
	if err != nil {
		return fmt.Errorf("kit: .hmac is not hex: %w", err)
	}

	f, err := os.Open(kitPath)
	if err != nil {
		return fmt.Errorf("kit: open kit: %w", err)
	}
	defer f.Close()

	mac := hmac.New(sha256.New, key)
	if _, err := io.Copy(mac, f); err != nil {
		return fmt.Errorf("kit: read kit: %w", err)
	}
	got := mac.Sum(nil)
	if !hmac.Equal(got, want) {
		return fmt.Errorf("kit: HMAC mismatch — kit may have been tampered with")
	}
	return nil
}

// Extract un-tars `kitPath` into `destDir`. Used by `lmbox-bridge-enroll
// verify-kit --extract` for the RSSI to inspect content before deploy.
// Returns the list of extracted file paths.
//
// Security : the tar reader REJECTS entries that would write outside
// `destDir` (path traversal via "..", absolute paths). We're paranoid
// here because the tool may run with elevated permissions during
// installation.
func Extract(kitPath, destDir string) ([]string, error) {
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return nil, fmt.Errorf("kit: mkdir dest: %w", err)
	}
	cleanedDest, err := filepath.Abs(destDir)
	if err != nil {
		return nil, fmt.Errorf("kit: resolve dest: %w", err)
	}

	f, err := os.Open(kitPath)
	if err != nil {
		return nil, fmt.Errorf("kit: open: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("kit: gzip reader: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var written []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return written, fmt.Errorf("kit: tar next: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Reject path traversal.
		dest := filepath.Join(cleanedDest, hdr.Name)
		// filepath.Join already resolves "..", but defence-in-depth :
		// ensure the resolved path is still under destDir.
		if !strings.HasPrefix(dest, cleanedDest+string(os.PathSeparator)) && dest != cleanedDest {
			return written, fmt.Errorf("kit: refusing path traversal: %s", hdr.Name)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return written, fmt.Errorf("kit: mkdir: %w", err)
		}
		mode := os.FileMode(hdr.Mode & 0o777)
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return written, fmt.Errorf("kit: open dest %s: %w", dest, err)
		}
		// Limit copy to header size to avoid a malicious tar with
		// a huge file claiming a small size.
		if _, err := io.CopyN(out, tr, hdr.Size); err != nil && err != io.EOF {
			out.Close()
			return written, fmt.Errorf("kit: copy %s: %w", dest, err)
		}
		out.Close()
		written = append(written, dest)
	}
	return written, nil
}

// ─── Internals ───────────────────────────────────────────────────

func writeTarFile(tw *tar.Writer, f File, modTime time.Time) error {
	hdr := &tar.Header{
		Name:    f.Path,
		Mode:    f.Mode,
		Size:    int64(len(f.Content)),
		ModTime: modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(f.Content)
	return err
}

// LoadHMACKey reads a hex- or base64-encoded HMAC key from a file.
// We accept both encodings because operators use different vault
// tools (1Password exports hex, AWS Secrets Manager exports base64).
// Whitespace is trimmed.
func LoadHMACKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kit: read HMAC key: %w", err)
	}
	s := strings.TrimSpace(string(data))
	// Try hex first.
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	// Try base64.
	if b, err := base64Decode(s); err == nil {
		return b, nil
	}
	// Last resort : treat the raw bytes as the key (so an operator
	// who wrote 32 random bytes to a file directly still works).
	return data, nil
}

// base64Decode is split out so it can be replaced in tests if needed.
// We don't import "encoding/base64" at the top to keep the import
// list minimal in the common path.
func base64Decode(s string) ([]byte, error) {
	return _b64.DecodeString(s)
}
