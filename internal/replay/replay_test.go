package replay

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

func newClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
}

func TestConsumeOnce(t *testing.T) {
	clock := newClock()
	cache := New(clock.Now, 10)
	key := Key("https://sp.example", "_request")

	assert.False(t, cache.Seen(key))

	require.NoError(t, cache.Consume(key, clock.Now().Add(time.Minute)))
	assert.True(t, cache.Seen(key))

	require.ErrorIs(t, cache.Consume(key, clock.Now().Add(time.Minute)), ErrReplayed)

	// Another request, or the same ID from another service provider, is
	// not affected.
	require.NoError(t, cache.Consume(Key("https://sp.example", "_other"), clock.Now().Add(time.Minute)))
	require.NoError(t, cache.Consume(Key("https://other.example", "_request"), clock.Now().Add(time.Minute)))
}

func TestKeySeparatesIssuerAndID(t *testing.T) {
	assert.NotEqual(t, Key("ab", "c"), Key("a", "bc"))
	assert.NotEqual(t, Key("a", ""), Key("", "a"))
}

func TestEntryExpires(t *testing.T) {
	clock := newClock()
	cache := New(clock.Now, 10)

	require.NoError(t, cache.Consume("k", clock.Now().Add(time.Minute)))

	clock.Advance(59 * time.Second)
	assert.True(t, cache.Seen("k"))
	require.ErrorIs(t, cache.Consume("k", clock.Now().Add(time.Minute)), ErrReplayed)

	clock.Advance(time.Second)
	assert.False(t, cache.Seen("k"))
	require.NoError(t, cache.Consume("k", clock.Now().Add(time.Minute)))
}

func TestFullCacheDropsExpiredEntriesOnly(t *testing.T) {
	clock := newClock()
	cache := New(clock.Now, 3)

	require.NoError(t, cache.Consume("short", clock.Now().Add(time.Minute)))
	require.NoError(t, cache.Consume("long-1", clock.Now().Add(time.Hour)))
	require.NoError(t, cache.Consume("long-2", clock.Now().Add(time.Hour)))

	// Full, and nothing has expired: an answered request is never
	// forgotten to make room.
	require.ErrorIs(t, cache.Consume("new", clock.Now().Add(time.Hour)), ErrFull)
	assert.True(t, cache.Seen("short"))

	clock.Advance(2 * time.Minute)

	require.NoError(t, cache.Consume("new", clock.Now().Add(time.Hour)))
	assert.Equal(t, 3, cache.Len())
	assert.True(t, cache.Seen("long-1"))
	assert.True(t, cache.Seen("long-2"))
	assert.False(t, cache.Seen("short"))
}

// Of many simultaneous answers to the same request, exactly one goes
// through.
func TestConsumeIsAtomic(t *testing.T) {
	clock := newClock()
	cache := New(clock.Now, DefaultCapacity)

	var (
		wg       sync.WaitGroup
		accepted atomic.Int32
	)

	for range 64 {
		wg.Go(func() {
			if cache.Consume("k", clock.Now().Add(time.Minute)) == nil {
				accepted.Add(1)
			}
		})
	}

	wg.Wait()

	assert.Equal(t, int32(1), accepted.Load())
}
