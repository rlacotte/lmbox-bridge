// Package audit implements a SHA-256 hash-chained audit log that
// matches the scheme used by the LMbox portal. Every entry includes
// the hash of the previous entry, so any tampering with a past line
// invalidates every subsequent line — detectable in O(N) by a
// single re-walk of the file.
//
// Design contract
// ───────────────
//  1. The chain has a deterministic genesis derived from a per-Bridge
//     enrolment string. Two Bridges in two different customer DMZs
//     thus produce chains that can never collide or be silently
//     swapped.
//  2. Every Append produces a complete, canonically-encoded entry
//     before hashing — so re-walking the chain from disk reproduces
//     the same hashes byte-for-byte, regardless of the writer's
//     Go runtime, locale, or JSON map ordering.
//  3. Append is goroutine-safe. The Bridge serves hundreds of
//     concurrent requests; the chain serialises them through a
//     single mutex.
//  4. Genesis is computed once at New() and never changes.
//     Subsequent reloads MUST resume from disk to keep the chain
//     unbroken.
//
// Non-goals
// ─────────
//  - We do not sign entries with the Bridge's private key. The chain
//    proves tamper-evidence (you can't silently change a past line),
//    not non-repudiation (the Bridge process itself is trusted).
//    Non-repudiation is the audit chain's job at the LMbox cloud
//    side, where each Bridge submission is signed.
//  - We do not implement compression or rotation here. systemd's
//    journald + logrotate handle that at the OS level; our file is
//    append-only and bounded by the operator's retention policy.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Entry is one audited event. JSON fields are stable: changing the
// shape breaks chain verification on existing files. New optional
// fields must be added with `omitempty` and at the end of the struct
// to preserve the canonical encoding order.
type Entry struct {
	Seq       uint64    `json:"seq"`
	Timestamp time.Time `json:"ts"`
	BoxSerial string    `json:"box"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	DurationMS int64    `json:"duration_ms"`
	ClientIP  string    `json:"client_ip"`
	// PrevHash and Hash are hex strings to keep the file
	// grep/jq-friendly for a RSSI inspecting the log.
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	// Optional fields below. Keep them last; do not reorder.
	Error string `json:"error,omitempty"`
}

// Chain is the appendable, hash-chained audit log.
type Chain struct {
	mu         sync.Mutex
	writer     io.Writer  // typically a *os.File opened O_APPEND
	bufWriter  *bufio.Writer
	lastHash   string
	nextSeq    uint64
	// reopenFn lets tests stub the file open behavior. Production
	// passes nil and we use the standard os.OpenFile semantics.
	reopenFn func() (io.WriteCloser, error)
}

// New constructs an empty chain. Use Resume to continue from an
// existing file.
//
// `genesis` MUST be a non-empty string unique to this Bridge
// enrolment. The recommended construction is
//
//	"lmbox-bridge/v1|customer=<id>|enrolled=<iso8601>"
//
// matching the LMbox portal's chain genesis convention so a single
// verifier can attest both chains side-by-side.
func New(writer io.Writer, genesis string) *Chain {
	if genesis == "" {
		panic("audit.New: genesis must not be empty")
	}
	h := sha256.Sum256([]byte("lmbox-bridge/audit-chain/v1|" + genesis))
	c := &Chain{
		writer:   writer,
		lastHash: hex.EncodeToString(h[:]),
		nextSeq:  1,
	}
	if writer != nil {
		c.bufWriter = bufio.NewWriter(writer)
	}
	return c
}

// Resume re-opens an existing audit file at `path`, replays it to
// reconstruct the last seq + last hash, and returns a Chain ready
// to append. The genesis must be the same as the one used when the
// file was first created — we verify by recomputing the first
// entry's prev_hash and matching it against the on-disk value.
func Resume(path, genesis string) (*Chain, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}

	c := New(f, genesis)
	// Replay from start to recover seq + lastHash. The genesis we
	// just set in New() must equal the prev_hash of seq=1 on disk
	// if any entries exist.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: seek: %w", err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line
	expectedPrev := c.lastHash
	var lastSeq uint64
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			f.Close()
			return nil, fmt.Errorf("audit: parse line: %w", err)
		}
		if e.PrevHash != expectedPrev {
			f.Close()
			return nil, fmt.Errorf("audit: chain break at seq=%d: prev_hash=%s, expected=%s",
				e.Seq, e.PrevHash, expectedPrev)
		}
		expectedPrev = e.Hash
		lastSeq = e.Seq
	}
	if err := scanner.Err(); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: scan: %w", err)
	}

	c.lastHash = expectedPrev
	c.nextSeq = lastSeq + 1
	// Seek back to end so subsequent writes append cleanly.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: seek end: %w", err)
	}
	return c, nil
}

// Append fills the seq, timestamp, prev_hash, and hash fields of e
// and writes it to the underlying writer. The caller need not set
// any of those; everything else (BoxSerial, Method, Path, etc.)
// MUST be filled.
//
// Returns the persisted Entry (copied so the caller can inspect
// without racing with future Appends).
func (c *Chain) Append(e Entry) (Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	e.Seq = c.nextSeq
	e.PrevHash = c.lastHash

	// Compute Hash on the canonical encoding (Hash field empty).
	hash, err := computeHash(e)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: hash: %w", err)
	}
	e.Hash = hash

	if c.bufWriter != nil {
		line, err := json.Marshal(e)
		if err != nil {
			return Entry{}, fmt.Errorf("audit: marshal: %w", err)
		}
		line = append(line, '\n')
		if _, err := c.bufWriter.Write(line); err != nil {
			return Entry{}, fmt.Errorf("audit: write: %w", err)
		}
		// Flush every entry. The Bridge isn't write-throughput-
		// bound (60 boxes × heartbeat/min ≈ 1 req/s typical) and
		// the audit value of a chained log evaporates if the buffer
		// holds the latest 100 lines through a crash.
		if err := c.bufWriter.Flush(); err != nil {
			return Entry{}, fmt.Errorf("audit: flush: %w", err)
		}
		// Best-effort fsync. If the underlying writer doesn't
		// support sync (e.g. tests with bytes.Buffer), skip.
		if syncer, ok := c.writer.(syncer); ok {
			if err := syncer.Sync(); err != nil {
				return Entry{}, fmt.Errorf("audit: fsync: %w", err)
			}
		}
	}

	c.lastHash = e.Hash
	c.nextSeq++
	return e, nil
}

// LastHash returns the most recently chained hash. Useful for the
// readiness probe + the periodic export to the cloud-side audit
// chain (which witnesses the Bridge's local chain so a customer's
// IT admin alone can't rewrite history).
func (c *Chain) LastHash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastHash
}

// Len returns the number of entries written so far. Powers the
// `lmbox_bridge_audit_chain_length` Prometheus gauge.
func (c *Chain) Len() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nextSeq - 1
}

// Verify walks the file at `path` from start to finish and confirms
// that every entry's prev_hash matches the previous entry's hash,
// and the first entry's prev_hash matches the genesis derived from
// `genesis`. Returns the number of verified entries and an error on
// the first chain break.
//
// This is the operator-facing "verify the chain" function — bound
// to the `lmbox-bridge verify` CLI subcommand and to a portal
// dashboard button.
func Verify(path, genesis string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("audit verify: open: %w", err)
	}
	defer f.Close()

	h := sha256.Sum256([]byte("lmbox-bridge/audit-chain/v1|" + genesis))
	expectedPrev := hex.EncodeToString(h[:])

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var n uint64
	var prevSeq uint64
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return n, fmt.Errorf("audit verify: parse line %d: %w", n+1, err)
		}
		if e.Seq != prevSeq+1 {
			return n, fmt.Errorf("audit verify: seq gap at entry %d: got seq=%d, expected %d",
				n+1, e.Seq, prevSeq+1)
		}
		if e.PrevHash != expectedPrev {
			return n, fmt.Errorf("audit verify: chain break at seq=%d: prev_hash=%s, expected=%s",
				e.Seq, e.PrevHash, expectedPrev)
		}
		recomputed, err := computeHash(e)
		if err != nil {
			return n, fmt.Errorf("audit verify: recompute hash at seq=%d: %w", e.Seq, err)
		}
		if recomputed != e.Hash {
			return n, fmt.Errorf("audit verify: hash mismatch at seq=%d: stored=%s, recomputed=%s",
				e.Seq, e.Hash, recomputed)
		}
		expectedPrev = e.Hash
		prevSeq = e.Seq
		n++
	}
	if err := scanner.Err(); err != nil {
		return n, fmt.Errorf("audit verify: scan: %w", err)
	}
	return n, nil
}

// ─── Internals ───────────────────────────────────────────────────

// computeHash returns hex(SHA-256(prev_hash || canonical(entry))).
// We blank the Hash field before marshaling because the hash is
// computed OVER the entry sans its own hash — otherwise the entry
// would need to hash itself recursively.
func computeHash(e Entry) (string, error) {
	clone := e
	clone.Hash = ""
	b, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	prev, err := hex.DecodeString(clone.PrevHash)
	if err != nil {
		return "", fmt.Errorf("decode prev_hash: %w", err)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// syncer is the subset of *os.File we need to fsync after append.
// Extracted as an interface so tests can use bytes.Buffer without
// fsync, and so we don't import "*os.File" semantics into hot path
// code unnecessarily.
type syncer interface {
	Sync() error
}
