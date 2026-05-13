package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChain_AppendAndVerify(t *testing.T) {
	var buf bytes.Buffer
	c := New(&buf, "test-genesis")

	for i := 0; i < 10; i++ {
		_, err := c.Append(Entry{
			BoxSerial: "BOX-TEST-001",
			Method:    "POST",
			Path:      "/api/heartbeats/BOX-TEST-001",
			Status:    200,
			BytesIn:   42,
			BytesOut:  8,
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Parse buffer back and verify every line chains.
	var prev string
	scanner := newLineScanner(&buf)
	count := 0
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("parse line %d: %v", count, err)
		}
		count++
		if count == 1 {
			// First entry's prev_hash must match the genesis.
			expected := New(nil, "test-genesis").LastHash()
			if e.PrevHash != expected {
				t.Fatalf("first prev_hash=%s, want=%s", e.PrevHash, expected)
			}
		} else {
			if e.PrevHash != prev {
				t.Fatalf("entry %d prev_hash=%s, want previous hash %s",
					count, e.PrevHash, prev)
			}
		}
		// Recompute the hash and check.
		recomputed, err := computeHash(e)
		if err != nil {
			t.Fatalf("recompute %d: %v", count, err)
		}
		if recomputed != e.Hash {
			t.Fatalf("hash mismatch at %d: stored=%s recomputed=%s", count, e.Hash, recomputed)
		}
		prev = e.Hash
	}
	if count != 10 {
		t.Fatalf("expected 10 entries, got %d", count)
	}
}

func TestChain_GenesisIsDifferentPerEnrolment(t *testing.T) {
	a := New(nil, "customer-a")
	b := New(nil, "customer-b")
	if a.LastHash() == b.LastHash() {
		t.Fatalf("two customers got same genesis hash: %s", a.LastHash())
	}
}

func TestChain_GenesisIsStableForSameInput(t *testing.T) {
	a := New(nil, "customer-a")
	b := New(nil, "customer-a")
	if a.LastHash() != b.LastHash() {
		t.Fatalf("same genesis produced different hash: %s vs %s", a.LastHash(), b.LastHash())
	}
}

func TestChain_PanicOnEmptyGenesis(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on empty genesis")
		}
	}()
	_ = New(nil, "")
}

func TestVerify_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	c := New(f, "rt-genesis")
	for i := 0; i < 5; i++ {
		if _, err := c.Append(Entry{BoxSerial: "BOX-X", Method: "GET", Path: "/", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	n, err := Verify(path, "rt-genesis")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 5 {
		t.Fatalf("verified %d, want 5", n)
	}
}

func TestVerify_DetectsTamper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	f, _ := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	c := New(f, "tamper-genesis")
	for i := 0; i < 5; i++ {
		if _, err := c.Append(Entry{BoxSerial: "BOX-Y", Method: "GET", Path: "/", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	// Tamper: change one byte of line 3 (BoxSerial → BOX-EVIL).
	data, _ := os.ReadFile(path)
	tampered := bytes.Replace(data, []byte("BOX-Y"), []byte("BOX-Z"), 1)
	os.WriteFile(path, tampered, 0o600)

	n, err := Verify(path, "tamper-genesis")
	if err == nil {
		t.Fatalf("expected verify to fail, got nil after %d entries", n)
	}
	if !strings.Contains(err.Error(), "hash mismatch") && !strings.Contains(err.Error(), "chain break") {
		t.Fatalf("expected tamper error, got: %v", err)
	}
}

func TestVerify_WrongGenesis(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	f, _ := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	c := New(f, "right-genesis")
	c.Append(Entry{BoxSerial: "BOX-Y", Method: "GET", Path: "/", Status: 200})
	f.Close()

	_, err := Verify(path, "wrong-genesis")
	if err == nil {
		t.Fatalf("expected verify to fail with wrong genesis")
	}
}

func TestResume_AppendsAfterReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Initial write.
	f, _ := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	c1 := New(f, "resume-genesis")
	c1.Append(Entry{BoxSerial: "BOX-Z", Method: "GET", Path: "/a", Status: 200})
	c1.Append(Entry{BoxSerial: "BOX-Z", Method: "GET", Path: "/b", Status: 200})
	f.Close()

	// Resume from disk.
	c2, err := Resume(path, "resume-genesis")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if c2.Len() != 2 {
		t.Fatalf("resume len=%d, want 2", c2.Len())
	}
	// Append one more — chain should remain intact.
	c2.Append(Entry{BoxSerial: "BOX-Z", Method: "GET", Path: "/c", Status: 200})

	// Now verify everything.
	n, err := Verify(path, "resume-genesis")
	if err != nil {
		t.Fatalf("verify after resume: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d, want 3", n)
	}
}

func TestResume_DetectsGenesisMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	f, _ := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	c := New(f, "right")
	c.Append(Entry{BoxSerial: "BOX-Z", Method: "GET", Path: "/", Status: 200})
	f.Close()

	_, err := Resume(path, "wrong")
	if err == nil {
		t.Fatalf("expected resume to detect genesis mismatch")
	}
}

// lineScanner is a tiny bufio.Scanner wrapper to avoid pulling in
// bufio in the test's top-level imports.
func newLineScanner(r interface{ Read([]byte) (int, error) }) *lScanner {
	return &lScanner{r: r}
}

type lScanner struct {
	r    interface{ Read([]byte) (int, error) }
	buf  []byte
	line []byte
}

func (s *lScanner) Scan() bool {
	for {
		if i := bytes.IndexByte(s.buf, '\n'); i >= 0 {
			s.line = s.buf[:i]
			s.buf = s.buf[i+1:]
			return true
		}
		tmp := make([]byte, 4096)
		n, err := s.r.Read(tmp)
		if n > 0 {
			s.buf = append(s.buf, tmp[:n]...)
		}
		if err != nil {
			return len(s.buf) > 0
		}
	}
}

func (s *lScanner) Bytes() []byte { return s.line }
