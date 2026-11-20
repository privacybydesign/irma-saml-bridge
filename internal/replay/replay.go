// Package replay remembers which AuthnRequests have been answered, so that a
// request cannot be turned into a second assertion.
package replay

import (
	"errors"
	"sync"
	"time"
)

// DefaultCapacity is the number of answered requests a cache holds. Entries
// are only added for requests a registered service provider signed and a
// user completed, so the bound is far above real traffic.
const DefaultCapacity = 500_000

var (
	// ErrReplayed is returned for a request that was answered before.
	ErrReplayed = errors.New("replay: request was already answered")

	// ErrFull is returned when the cache cannot take another request.
	ErrFull = errors.New("replay: cache is full")
)

// Cache is an in-memory set of answered requests. It is safe for concurrent
// use. It is not shared between replicas: a request answered by one replica
// is not known to another.
type Cache struct {
	mu       sync.Mutex
	now      func() time.Time
	capacity int
	until    map[string]time.Time
}

// New returns an empty cache.
func New(now func() time.Time, capacity int) *Cache {
	return &Cache{now: now, capacity: capacity, until: map[string]time.Time{}}
}

// Key identifies a request by the service provider that issued it and its
// ID. IDs of different service providers do not collide.
func Key(issuer, requestID string) string {
	return issuer + "\x00" + requestID
}

// Seen reports whether key was consumed and is still remembered.
func (c *Cache) Seen(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	until, ok := c.until[key]

	return ok && c.now().Before(until)
}

// Consume records key until the given time. It returns ErrReplayed when key
// is already recorded; checking and recording are one step, so of two
// concurrent calls only one succeeds.
func (c *Cache) Consume(key string, until time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()

	if prev, ok := c.until[key]; ok && now.Before(prev) {
		return ErrReplayed
	}

	if len(c.until) >= c.capacity {
		for k, t := range c.until {
			if !now.Before(t) {
				delete(c.until, k)
			}
		}

		if len(c.until) >= c.capacity {
			return ErrFull
		}
	}

	c.until[key] = until

	return nil
}

// Len returns the number of remembered requests, expired ones included.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.until)
}
