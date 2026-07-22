package conformance_test

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI/conformance"
)

// The suite is tested against stores that are broken in the two ways real
// implementations are broken. A conformance suite that has never been shown to
// fail anything is a claim rather than a check, and the claim is the thing a
// host would be relying on.
//
// Each store below is a shape that gets written, reviewed and shipped. Neither
// is a strawman: both behave correctly in a quiet test environment, which is
// exactly why the defects reach production.

// --- store 1: check, act, then mark -------------------------------------
//
// The lock is released for the duration of the effect, so every concurrent
// presentation of the same credential passes the check before any of them
// marks it. This is the double spend.

type checkThenAct struct {
	mu        sync.Mutex
	consumed  map[string]bool
	committed map[string][]byte
}

type storeKey struct{}

func (s *checkThenAct) Consume(ctx context.Context, rec boundedauth.Consumption, effect func(context.Context) error) error {
	s.mu.Lock()
	spent := s.consumed[rec.ID]
	s.mu.Unlock()
	if spent {
		return boundedauth.ErrAlreadyConsumed
	}

	if err := effect(context.WithValue(ctx, storeKey{}, s)); err != nil {
		return err
	}

	s.mu.Lock()
	s.consumed[rec.ID] = true
	s.mu.Unlock()
	return nil
}

// --- store 2: mark first, in its own transaction ------------------------
//
// Single use is enforced, correctly, and committed immediately — then the
// effect runs outside it. A failed effect leaves the credential spent and the
// customer holding an authorisation they cannot use for a payment that never
// happened.

type markFirst struct {
	mu        sync.Mutex
	consumed  map[string]bool
	committed map[string][]byte
}

func (s *markFirst) Consume(ctx context.Context, rec boundedauth.Consumption, effect func(context.Context) error) error {
	s.mu.Lock()
	if s.consumed[rec.ID] {
		s.mu.Unlock()
		return boundedauth.ErrAlreadyConsumed
	}
	s.consumed[rec.ID] = true // committed here, never rolled back
	s.mu.Unlock()

	return effect(context.WithValue(ctx, storeKey{}, s))
}

// --- store 3: invokes the effect twice ----------------------------------
//
// Single use is correct and the lock is held across the effect, so this store
// passes the concurrency and replay checks — but it runs the effect twice, the
// shape of a store that retries the effect internally. A real payout would be
// delivered twice. Only EffectRunsExactlyOnce catches it, which is exactly why
// that check has to be demonstrated against something.

type doubleEffect struct {
	mu        sync.Mutex
	consumed  map[string]bool
	committed map[string][]byte
}

func (s *doubleEffect) Consume(ctx context.Context, rec boundedauth.Consumption, effect func(context.Context) error) error {
	s.mu.Lock()
	spent := s.consumed[rec.ID]
	s.mu.Unlock()
	if spent {
		return boundedauth.ErrAlreadyConsumed
	}
	ctx = context.WithValue(ctx, storeKey{}, s)
	if err := effect(ctx); err != nil {
		return err
	}
	if err := effect(ctx); err != nil { // the bug: the effect runs a second time
		return err
	}
	s.mu.Lock()
	s.consumed[rec.ID] = true
	s.mu.Unlock()
	return nil
}

func (s *doubleEffect) put(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.committed[key] = []byte("e")
}
func (s *doubleEffect) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.committed[key]
	return ok
}
func (s *doubleEffect) spent(id string) bool { s.mu.Lock(); defer s.mu.Unlock(); return s.consumed[id] }

// Both stores write straight through, so an effect's write survives the
// effect's own failure.
type writer interface {
	put(key string)
	has(key string) bool
	spent(id string) bool
}

func (s *checkThenAct) put(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.committed[key] = []byte("e")
}
func (s *checkThenAct) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.committed[key]
	return ok
}
func (s *checkThenAct) spent(id string) bool { s.mu.Lock(); defer s.mu.Unlock(); return s.consumed[id] }

func (s *markFirst) put(key string) { s.mu.Lock(); defer s.mu.Unlock(); s.committed[key] = []byte("e") }
func (s *markFirst) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.committed[key]
	return ok
}
func (s *markFirst) spent(id string) bool { s.mu.Lock(); defer s.mu.Unlock(); return s.consumed[id] }

// --- running the suite against them -------------------------------------

// recorder stands in for *testing.T so a check can fail without failing the
// real test. Fatalf must abort its check, which testing.T does by ending the
// goroutine; here it panics and the runner recovers.
type recorder struct {
	mu     sync.Mutex
	failed bool
}

type abort struct{}

func (r *recorder) Helper()               {}
func (r *recorder) fail()                 { r.mu.Lock(); r.failed = true; r.mu.Unlock() }
func (r *recorder) Error(args ...any)     { r.fail() }
func (r *recorder) Errorf(string, ...any) { r.fail() }
func (r *recorder) Fatal(args ...any)     { r.fail(); panic(abort{}) }
func (r *recorder) Fatalf(string, ...any) { r.fail(); panic(abort{}) }

func runCheck(c conformance.Check, h conformance.Harness) (failed bool) {
	r := &recorder{}
	defer func() {
		if v := recover(); v != nil {
			if _, ok := v.(abort); !ok {
				panic(v)
			}
		}
		failed = r.failed
	}()
	c.Run(r, h)
	return r.failed
}

func harnessFor(newStore func() (boundedauth.Store, writer)) (conformance.Harness, func() writer) {
	var current writer
	h := conformance.Harness{
		NewStore: func(t conformance.TB) boundedauth.Store {
			s, w := newStore()
			current = w
			return s
		},
		Write: func(ctx context.Context, key string) error {
			ctx.Value(storeKey{}).(writer).put(key)
			return nil
		},
		Committed: func(t conformance.TB, key string) bool { return current.has(key) },
		Consumed:  func(t conformance.TB, id string) bool { return current.spent(id) },
	}
	return h, func() writer { return current }
}

func caughtBy(h conformance.Harness) map[string]bool {
	out := map[string]bool{}
	for _, c := range conformance.Checks {
		if runCheck(c, h) {
			out[c.Name] = true
		}
	}
	return out
}

func TestSuiteCatchesRealAntiPatterns(t *testing.T) {
	cases := []struct {
		name  string
		store func() (boundedauth.Store, writer)
		// The defects this store has. Named individually rather than counted,
		// so a change that stops detecting one specific failure mode cannot be
		// masked by another check still failing.
		mustCatch []string
	}{
		{
			name: "check-then-act releases the lock across the effect",
			store: func() (boundedauth.Store, writer) {
				s := &checkThenAct{consumed: map[string]bool{}, committed: map[string][]byte{}}
				return s, s
			},
			mustCatch: []string{
				"ConcurrentPresentationSpendsExactlyOnce",
				"FailedEffectRollsBackItsOwnWrite",
			},
		},
		{
			name: "mark-first commits consumption before the effect",
			store: func() (boundedauth.Store, writer) {
				s := &markFirst{consumed: map[string]bool{}, committed: map[string][]byte{}}
				return s, s
			},
			mustCatch: []string{
				"FailedEffectRollsBackConsumption",
				"FailedEffectRollsBackItsOwnWrite",
				"CredentialIsSpendableAfterAFailedEffect",
			},
		},
		{
			name: "double-effect runs the effect twice",
			store: func() (boundedauth.Store, writer) {
				s := &doubleEffect{consumed: map[string]bool{}, committed: map[string][]byte{}}
				return s, s
			},
			mustCatch: []string{"EffectRunsExactlyOnce"},
		},
	}

	// Every defect the suite claims to detect must be detected by at least one
	// of these stores, or the check is untested.
	covered := map[string]bool{}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := harnessFor(tc.store)
			caught := caughtBy(h)
			for _, must := range tc.mustCatch {
				if !caught[must] {
					t.Errorf("the suite passed this store on %q; that check does not "+
						"detect what it claims to", must)
				}
				covered[must] = true
			}
			// A suite that rejects every store is no more informative than one
			// that accepts every store.
			if len(caught) == len(conformance.Checks) {
				t.Error("every check failed; the suite is not discriminating")
			}
			t.Logf("caught %d of %d: %s", len(caught), len(conformance.Checks),
				strings.Join(sorted(caught), ", "))
		})
	}

	// The four checks that exist for the failures ordinary testing misses are
	// the ones that must be demonstrated. The remaining checks are basic
	// behaviour that the reference implementation exercises.
	for _, must := range []string{
		"ConcurrentPresentationSpendsExactlyOnce",
		"FailedEffectRollsBackConsumption",
		"FailedEffectRollsBackItsOwnWrite",
		"CredentialIsSpendableAfterAFailedEffect",
		"EffectRunsExactlyOnce",
	} {
		if !covered[must] {
			t.Errorf("no broken store demonstrates %q; it has never been shown to fail", must)
		}
	}
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
