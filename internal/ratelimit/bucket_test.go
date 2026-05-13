package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBucket_AllowDecrements(t *testing.T) {
	b := NewBucket(10, 5)
	for i := 0; i < 5; i++ {
		if !b.Allow() {
			t.Fatalf("Allow %d denied unexpectedly (tokens=%.2f)", i, b.Tokens())
		}
	}
	// Bucket empty now.
	if b.Allow() {
		t.Fatalf("Allow should have failed when bucket is empty")
	}
}

func TestBucket_RefillsAtRate(t *testing.T) {
	b := NewBucket(100, 5) // 100 tokens/s, burst 5
	// Drain.
	for i := 0; i < 5; i++ {
		b.Allow()
	}
	if b.Allow() {
		t.Fatalf("bucket should be empty after draining")
	}
	// Wait 50ms → should refill ~5 tokens.
	time.Sleep(60 * time.Millisecond)
	allowed := 0
	for i := 0; i < 5; i++ {
		if b.Allow() {
			allowed++
		}
	}
	if allowed < 3 {
		t.Fatalf("expected >=3 tokens refilled after 60ms at 100tok/s, got %d", allowed)
	}
}

func TestBucket_BurstCap(t *testing.T) {
	b := NewBucket(1, 10) // 1 tok/s, burst 10
	// Wait long enough for unbounded refill — should cap at burst.
	time.Sleep(50 * time.Millisecond)
	b.Allow() // trigger refill calculation
	if b.Tokens() > 10 {
		t.Fatalf("tokens=%.2f exceeded burst=10", b.Tokens())
	}
}

func TestBucket_Concurrent(t *testing.T) {
	b := NewBucket(1000, 100)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if b.Allow() {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	// 50 goroutines × 10 attempts = 500 tries. With burst 100 we
	// expect at least 100 allowed but not more than 500.
	got := allowed.Load()
	if got < 100 || got > 500 {
		t.Fatalf("concurrent allowed=%d outside [100, 500]", got)
	}
}

func TestMulti_PerKeyIsolation(t *testing.T) {
	m := NewMulti(2, 2, 0, 0) // 2 tok/s, burst 2, no global
	// Drain box A.
	for i := 0; i < 2; i++ {
		if ok, _ := m.Allow("BOX-A"); !ok {
			t.Fatalf("BOX-A draining failed at %d", i)
		}
	}
	// BOX-A is empty.
	if ok, _ := m.Allow("BOX-A"); ok {
		t.Fatalf("BOX-A should be empty")
	}
	// BOX-B fresh.
	if ok, _ := m.Allow("BOX-B"); !ok {
		t.Fatalf("BOX-B should be allowed (isolated bucket)")
	}
}

func TestMulti_GlobalCap(t *testing.T) {
	m := NewMulti(1e6, 1e6, 5, 5) // virtually unlimited per-key, global=5
	for i := 0; i < 5; i++ {
		if ok, _ := m.Allow("BOX-X"); !ok {
			t.Fatalf("first 5 should be allowed, %d denied", i)
		}
	}
	ok, deniedBy := m.Allow("BOX-X")
	if ok {
		t.Fatalf("should be denied by global bucket")
	}
	if deniedBy != "global" {
		t.Fatalf("expected denial by global, got %s", deniedBy)
	}
}

func TestMulti_GlobalDenialDoesNotDrainPerKey(t *testing.T) {
	// Global bucket exhausts first; per-key should still have tokens
	// when global eventually refills.
	m := NewMulti(1, 5, 1, 1) // per-key burst 5, global burst 1
	// First request consumes 1 global + 1 per-key.
	if ok, _ := m.Allow("BOX-Q"); !ok {
		t.Fatalf("first request denied")
	}
	// Second request: global empty → denied by global.
	if ok, by := m.Allow("BOX-Q"); ok || by != "global" {
		t.Fatalf("expected global denial, got ok=%v by=%s", ok, by)
	}
	// Per-key should still have ~4 tokens (1 consumed earlier).
	// We can't observe internal state without a peek API, but we
	// can wait for global to refill and try again.
	time.Sleep(1100 * time.Millisecond) // wait ~1 token of global refill
	// Should succeed now — per-key has tokens, global has 1 fresh.
	if ok, _ := m.Allow("BOX-Q"); !ok {
		t.Fatalf("after global refill, request should succeed")
	}
}

func TestMulti_SnapshotShape(t *testing.T) {
	m := NewMulti(10, 10, 0, 0)
	m.Allow("BOX-A")
	m.Allow("BOX-B")
	s := m.Snapshot()
	if len(s) != 2 {
		t.Fatalf("snapshot len=%d, want 2", len(s))
	}
	if _, ok := s["BOX-A"]; !ok {
		t.Fatalf("BOX-A missing from snapshot")
	}
}
