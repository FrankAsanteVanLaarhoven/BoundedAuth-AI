// Package memory is a reference [boundedauth.Store] that keeps everything in
// process memory.
//
// It exists for two reasons, and neither of them is production use.
//
// First, it is the executable definition of the contract. The conformance suite
// is a set of assertions; this is something that satisfies them, so an
// implementer has a worked example of what "atomically with the effect" means
// rather than only a description of it.
//
// Second, it demonstrates that the contract is satisfiable without a database.
// The property under test is transactional, not relational: stage the effect's
// writes, apply them only when the effect returns successfully, discard them
// otherwise, and hold the credential's identity against concurrent attempts for
// that whole span.
//
// It is not durable, so it does not survive a restart, and everything in it is
// lost. Use a real database for anything that matters.
package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
)

// ErrNoTransaction means [Store.Put] was called outside an effect. It is the
// error a host would get for doing the thing the conformance suite exists to
// catch: performing the effect on a connection unrelated to the one that spent
// the credential.
var ErrNoTransaction = errors.New("memory: Put called outside a Consume effect")

type txKey struct{}

type tx struct{ pending map[string][]byte }

type Store struct {
	// One lock covers both consumption and commitment. Finer locking would be
	// faster and would also be the place a subtle double-spend hides; this
	// implementation is a reference, so it takes the boring option.
	mu        sync.Mutex
	consumed  map[string]boundedauth.Consumption
	committed map[string][]byte
}

func New() *Store {
	return &Store{
		consumed:  map[string]boundedauth.Consumption{},
		committed: map[string][]byte{},
	}
}

// Consume spends the credential and applies the effect, or does neither.
//
// The lock is held across the effect. That is deliberate: releasing it to run
// the effect is exactly the window in which a second presentation of the same
// credential passes its own check, and the resulting double spend is not
// reproducible on demand.
func (s *Store) Consume(ctx context.Context, rec boundedauth.Consumption, effect func(context.Context) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, spent := s.consumed[rec.ID]; spent {
		// Refused before the effect runs. A store that runs the effect first
		// and reports the replay afterwards has already moved the money.
		return boundedauth.ErrAlreadyConsumed
	}

	t := &tx{pending: map[string][]byte{}}
	if err := effect(context.WithValue(ctx, txKey{}, t)); err != nil {
		// Nothing is applied and nothing is recorded, so the credential
		// remains spendable and the customer is not asked to authorise a
		// payment they already approved.
		return err
	}

	s.consumed[rec.ID] = rec
	for k, v := range t.pending {
		s.committed[k] = v
	}
	return nil
}

// Put stages a write inside an effect. It is visible to [Store.Get] only if the
// effect returns nil.
func (s *Store) Put(ctx context.Context, key string, value []byte) error {
	t, ok := ctx.Value(txKey{}).(*tx)
	if !ok {
		return ErrNoTransaction
	}
	t.pending[key] = value
	return nil
}

// Get reads a committed value. It must not be called from inside an effect:
// the lock is held for that whole span, deliberately, and a reader that wants
// to observe its own uncommitted write is asking the wrong question.
func (s *Store) Get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.committed[key]
	return v, ok
}

// Consumption returns the record of a spent credential.
func (s *Store) Consumption(id string) (boundedauth.Consumption, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.consumed[id]
	return c, ok
}
