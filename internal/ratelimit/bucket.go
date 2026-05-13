// Package ratelimit implements a token-bucket rate limiter that the
// Bridge applies on two axes :
//
//  1. Per-box bucket (keyed by client cert CN, i.e. the box serial).
//     A misbehaving box can't take the Bridge or the LMbox cloud out.
//  2. Global bucket across the whole Bridge process. Belt-and-braces
//     against a coordinated swarm of boxes (e.g. a bug in the agent
//     runtime that fires retries in a tight loop).
//
// Why token bucket and not leaky bucket / fixed window
// ────────────────────────────────────────────────────
//   - Bursts are natural: a box just came online and replays buffered
//     heartbeats. Token bucket absorbs the burst up to the bucket
//     capacity, then steadies out to the refill rate. Leaky bucket
//     spreads identical request volumes over time, which is wrong
//     here — we want to LET the legitimate burst through.
//   - Fixed window has edge effects (2× the rate at the boundary)
//     and is hard for a RSSI to reason about ("why did it allow 200
//     in a single second?").
//
// Concurrency model
// ─────────────────
// Per-box buckets live in a sync.Map (cheap concurrent reads on the
// hot path). On first request for a given serial we lock the map
// briefly to insert; thereafter it's a sync.Map load. Each Bucket
// has its own mutex protecting `tokens` and `last`. Fine-grained
// locks scale better than a single mutex on the map for the 60+
// concurrent boxes we target.
//
// Memory bound
// ────────────
// A box that never reconnects keeps its bucket entry forever.
// At 60 boxes that's ~3 KB — fine. At 600 boxes (series A target)
// still ~30 KB. We don't expire entries; the cost of a stale entry
// is negligible compared to the bookkeeping a sweeper would add.
// If this ever becomes an issue, switch to an LRU.
package ratelimit

import (
	"sync"
	"time"
)

// Bucket is a single token bucket. Refills at `rate` tokens per
// second, capped at `burst`. Allow() consumes one token if available.
type Bucket struct {
	rate  float64 // tokens / sec
	burst float64 // capacity

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// NewBucket returns a Bucket initialised at full capacity. Starting
// full means a freshly-online box gets its expected burst budget
// rather than being throttled for the first 10 seconds.
func NewBucket(rate, burst float64) *Bucket {
	return &Bucket{
		rate:   rate,
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
	}
}

// Allow consumes one token if available, returning true. Returns
// false if the bucket is empty (the caller MUST reject the request).
// Cheap: one Lock + one time.Since on the hot path.
func (b *Bucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Tokens returns the current token count. For tests + metrics only;
// callers SHOULD use Allow() to consume.
func (b *Bucket) Tokens() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens
}

// Multi keeps one Bucket per key (the box serial). The global bucket
// is checked in addition to the per-key bucket so we throttle both
// axes simultaneously.
type Multi struct {
	rate   float64
	burst  float64
	global *Bucket
	keys   sync.Map // string -> *Bucket
}

// NewMulti constructs a Multi with the per-key parameters and an
// optional global cap. If globalRate is 0, the global bucket is
// disabled.
func NewMulti(rate, burst, globalRate, globalBurst float64) *Multi {
	m := &Multi{rate: rate, burst: burst}
	if globalRate > 0 {
		m.global = NewBucket(globalRate, globalBurst)
	}
	return m
}

// Allow consumes one token from the per-key bucket AND (if enabled)
// one from the global bucket. Returns the outcome and the bucket
// that denied the request when false. The caller logs this so the
// operator sees whether throttling is per-box (one bad client) or
// global (capacity issue).
//
// IMPORTANT: per-key is checked first. If global is exhausted, we
// don't decrement per-key (so the legitimate box's bucket isn't
// drained by a global storm).
func (m *Multi) Allow(key string) (allowed bool, deniedBy string) {
	b := m.getOrCreate(key)

	// Check global first WITHOUT consuming so we don't drain per-key
	// when global is empty.
	if m.global != nil {
		m.global.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(m.global.last).Seconds()
		m.global.last = now
		m.global.tokens += elapsed * m.global.rate
		if m.global.tokens > m.global.burst {
			m.global.tokens = m.global.burst
		}
		if m.global.tokens < 1 {
			m.global.mu.Unlock()
			return false, "global"
		}
		// Consume global now since per-key still might deny — but
		// global state already reflects this attempt, which is the
		// correct semantic (the attempt costs a global slot whether
		// or not it ultimately succeeded).
		m.global.tokens--
		m.global.mu.Unlock()
	}

	if !b.Allow() {
		return false, "per-key"
	}
	return true, ""
}

func (m *Multi) getOrCreate(key string) *Bucket {
	if v, ok := m.keys.Load(key); ok {
		return v.(*Bucket)
	}
	// Create a fresh bucket. LoadOrStore handles the race where two
	// goroutines insert simultaneously: only one wins, the other
	// gets the winner's bucket.
	created := NewBucket(m.rate, m.burst)
	actual, _ := m.keys.LoadOrStore(key, created)
	return actual.(*Bucket)
}

// Snapshot returns a copy of all per-key bucket states. Used by the
// admin/debug endpoint, not by hot-path code.
func (m *Multi) Snapshot() map[string]float64 {
	out := map[string]float64{}
	m.keys.Range(func(k, v interface{}) bool {
		out[k.(string)] = v.(*Bucket).Tokens()
		return true
	})
	return out
}
