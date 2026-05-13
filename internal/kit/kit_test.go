package kit

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAndVerify_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	dir := t.TempDir()
	out := filepath.Join(dir, "test-kit.tar.gz")
	files := []File{
		{Path: "certs/bridge-server.crt", Mode: 0o644, Content: []byte("cert-bytes")},
		{Path: "certs/bridge-server.key", Mode: 0o600, Content: []byte("key-bytes")},
		{Path: "config.yaml", Mode: 0o644, Content: []byte("listen: ...")},
	}
	hexMac, err := Build(out, files, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(hexMac) != 64 {
		t.Fatalf("hmac length=%d, want 64 hex chars", len(hexMac))
	}
	// .hmac file must exist next to the kit.
	mac, err := os.ReadFile(out + ".hmac")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(mac)) != hexMac {
		t.Fatalf(".hmac file content mismatch: file=%q vs return=%q",
			strings.TrimSpace(string(mac)), hexMac)
	}

	// Verify happy path.
	if err := Verify(out, key); err != nil {
		t.Fatalf("verify happy: %v", err)
	}
}

func TestVerify_DetectsTamper(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	out := filepath.Join(dir, "kit.tar.gz")
	if _, err := Build(out, []File{
		{Path: "x.txt", Mode: 0o644, Content: []byte("hello")},
	}, key); err != nil {
		t.Fatal(err)
	}

	// Tamper one byte.
	data, _ := os.ReadFile(out)
	data[len(data)/2] ^= 0xFF
	os.WriteFile(out, data, 0o644)

	if err := Verify(out, key); err == nil {
		t.Fatal("expected verify to detect tamper")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	keyA := make([]byte, 32)
	rand.Read(keyA)
	keyB := make([]byte, 32)
	rand.Read(keyB)
	dir := t.TempDir()
	out := filepath.Join(dir, "kit.tar.gz")
	if _, err := Build(out, []File{{Path: "x", Mode: 0o644, Content: []byte("y")}}, keyA); err != nil {
		t.Fatal(err)
	}
	if err := Verify(out, keyB); err == nil {
		t.Fatal("expected verify to reject wrong key")
	}
}

func TestExtract_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	out := filepath.Join(dir, "kit.tar.gz")
	files := []File{
		{Path: "certs/a.pem", Mode: 0o644, Content: []byte("a")},
		{Path: "config.yaml", Mode: 0o644, Content: []byte("c")},
	}
	if _, err := Build(out, files, key); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "extracted")
	written, err := Extract(out, dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 2 {
		t.Fatalf("written=%d, want 2", len(written))
	}
	got, _ := os.ReadFile(filepath.Join(dest, "certs/a.pem"))
	if string(got) != "a" {
		t.Fatalf("content mismatch: %q", got)
	}
}

func TestExtract_RejectsPathTraversal(t *testing.T) {
	// Build a kit with a malicious filename.
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	out := filepath.Join(dir, "kit.tar.gz")
	// The path "../../etc/passwd" should be rejected by Extract.
	files := []File{
		{Path: "../../etc/passwd", Mode: 0o644, Content: []byte("rooty")},
	}
	if _, err := Build(out, files, key); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "extracted")
	_, err := Extract(out, dest)
	if err == nil {
		t.Fatal("expected extract to refuse path traversal")
	}
}

func TestBuild_DeterministicForSameInputs(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	out1 := filepath.Join(dir, "k1.tar.gz")
	out2 := filepath.Join(dir, "k2.tar.gz")
	files := []File{
		{Path: "b.txt", Mode: 0o644, Content: []byte("B")},
		{Path: "a.txt", Mode: 0o644, Content: []byte("A")},
	}
	h1, err := Build(out1, files, key)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Build(out2, files, key)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("non-deterministic builds: %s vs %s", h1, h2)
	}
}

func TestLoadHMACKey_AcceptsHex(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 32)
	rand.Read(raw)
	path := filepath.Join(dir, "k.hex")
	os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0o600)
	got, err := LoadHMACKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("hex decode mismatch")
	}
}

func TestLoadHMACKey_AcceptsBase64(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 32)
	rand.Read(raw)
	path := filepath.Join(dir, "k.b64")
	os.WriteFile(path, []byte(_b64.EncodeToString(raw)), 0o600)
	got, err := LoadHMACKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("base64 decode mismatch")
	}
}
