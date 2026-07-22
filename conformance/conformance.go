// Package conformance checks that a host's [boundedauth.Store] actually spends
// a credential exactly once, atomically with the effect it authorises.
//
// # Why this exists
//
// The interesting requirement in bounded authority is not the cryptography. The
// signature checking is a hundred lines and either works or fails obviously.
// The requirement that gets shipped broken is atomicity: that spending the
// credential and doing the work commit together.
//
// A broken implementation passes normal testing. It passes code review, because
// the code reads correctly — look up, check, mark, act. It fails under
// concurrency and under partial failure, which is to say it fails in
// production, on the paths where money is involved, in ways that surface as a
// customer charged twice or an authorisation that could be replayed.
//
// So this suite tries specifically to break those. It runs the failure modes
// that do not occur in a quiet test environment: simultaneous presentation of
// the same credential, and an effect that fails after the credential has
// notionally been spent.
//
// # Using it
//
//	func TestConformance(t *testing.T) {
//	    conformance.Run(t, conformance.Harness{
//	        NewStore:  func(t *testing.T) boundedauth.Store { ... },
//	        Write:     func(ctx context.Context, key string) error { ... },
//	        Committed: func(t *testing.T, key string) bool { ... },
//	        Consumed:  func(t *testing.T, id string) bool { ... },
//	    })
//	}
//
// A host that passes this has demonstrated the property. A host that cannot
// implement Write against the transaction Consume opened has learned something
// important: their store cannot offer the guarantee, whatever its code says.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
)

// TB is the part of *testing.T the checks use.
//
// It is an interface rather than *testing.T for one reason: it lets the suite
// be run against a recorder, so the suite itself can be tested against a
// deliberately broken store. A conformance suite that has never been shown to
// fail anything is a claim, not a check — see conformance_test.go, where a
// check-then-act store is run through these and must fail.
type TB interface {
	Helper()
	Error(args ...any)
	Errorf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// Check is one named requirement.
type Check struct {
	Name string
	Run  func(t TB, h Harness)
}

// Checks is every requirement, exported so a host can run one in isolation
// while fixing it, and so the set is enumerable in a compliance document.
var Checks = []Check{
	{"SpendsOnce", spendsOnce},
	{"RefusesReplay", refusesReplay},
	{"DistinctCredentialsBothSpend", distinct},
	{"FailedEffectRollsBackConsumption", failedEffect},
	{"FailedEffectRollsBackItsOwnWrite", failedEffectWrite},
	{"CredentialIsSpendableAfterAFailedEffect", retryAfterFailure},
	{"ConcurrentPresentationSpendsExactlyOnce", concurrent},
	{"EffectRunsExactlyOnce", effectOnce},
}

// Harness is what the host supplies so the suite can inspect durable state.
type Harness struct {
	// NewStore returns a fresh, empty store. It is called once per test.
	NewStore func(t TB) boundedauth.Store

	// Write performs a durable side effect keyed by key.
	//
	// It MUST run inside the transaction Consume opened — that is the entire
	// property under test. The context passed to the effect is how a host
	// carries that transaction; if Write ignores it and opens its own
	// connection, this suite will fail, correctly.
	Write func(ctx context.Context, key string) error

	// Committed reports whether Write(key) is durably visible now, as observed
	// from OUTSIDE any transaction the suite is in.
	Committed func(t TB, key string) bool

	// Consumed reports whether the credential ID is durably recorded as spent.
	Consumed func(t TB, id string) bool
}

var errEffectFailed = errors.New("effect failed deliberately")

func rec(id string) boundedauth.Consumption {
	return boundedauth.Consumption{
		ID: id, Issuer: "conformance", Subject: "subject",
		Method: boundedauth.MethodPasskey, Binding: "binding-" + id,
		Reference: "ref-" + id, ConsumedAt: time.Unix(1700000000, 0).UTC(),
	}
}

// Run executes the suite.
func Run(t *testing.T, h Harness) {
	t.Helper()
	if h.NewStore == nil || h.Write == nil || h.Committed == nil || h.Consumed == nil {
		t.Fatal("conformance: Harness requires NewStore, Write, Committed and Consumed")
	}

	for _, c := range Checks {
		t.Run(c.Name, func(t *testing.T) { c.Run(t, h) })
	}
}

func spendsOnce(t TB, h Harness) {
	s, ctx := h.NewStore(t), context.Background()
	r := rec("cred-spend")
	if err := s.Consume(ctx, r, func(ctx context.Context) error {
		return h.Write(ctx, r.ID)
	}); err != nil {
		t.Fatalf("first consumption failed: %v", err)
	}
	if !h.Consumed(t, r.ID) {
		t.Error("the credential is not recorded as consumed after a successful consumption")
	}
	if !h.Committed(t, r.ID) {
		t.Error("the effect is not durably visible after a successful consumption")
	}
}

func refusesReplay(t TB, h Harness) {
	s, ctx := h.NewStore(t), context.Background()
	r := rec("cred-replay")
	if err := s.Consume(ctx, r, func(ctx context.Context) error { return h.Write(ctx, r.ID) }); err != nil {
		t.Fatalf("first consumption failed: %v", err)
	}

	ran := false
	err := s.Consume(ctx, r, func(ctx context.Context) error {
		ran = true
		return h.Write(ctx, r.ID+"-second")
	})
	if !errors.Is(err, boundedauth.ErrAlreadyConsumed) {
		t.Fatalf("replaying a spent credential returned %v, want ErrAlreadyConsumed", err)
	}
	// The effect must not run at all. A store that runs the effect and then
	// reports the replay has already moved the money.
	if ran {
		t.Error("the effect ran for a credential that had already been spent")
	}
	if h.Committed(t, r.ID+"-second") {
		t.Error("a replayed credential produced a second durable effect")
	}
}

func distinct(t TB, h Harness) {
	s, ctx := h.NewStore(t), context.Background()
	for _, id := range []string{"cred-a", "cred-b"} {
		if err := s.Consume(ctx, rec(id), func(ctx context.Context) error {
			return h.Write(ctx, id)
		}); err != nil {
			t.Fatalf("consuming %s failed: %v", id, err)
		}
	}
	for _, id := range []string{"cred-a", "cred-b"} {
		if !h.Consumed(t, id) || !h.Committed(t, id) {
			t.Errorf("%s did not complete; the store is serialising unrelated credentials", id)
		}
	}
}

// The requirement most implementations miss. If the effect fails, the customer
// was not charged, so their authorisation must still be spendable — otherwise
// they are asked to re-approve a payment they already approved, and the
// implementation has turned a retryable failure into a lost authorisation.
func failedEffect(t TB, h Harness) {
	s, ctx := h.NewStore(t), context.Background()
	r := rec("cred-fail")
	err := s.Consume(ctx, r, func(ctx context.Context) error { return errEffectFailed })
	if !errors.Is(err, errEffectFailed) {
		t.Fatalf("Consume returned %v; the effect's error must reach the caller", err)
	}
	if h.Consumed(t, r.ID) {
		t.Fatal("the credential was recorded as spent even though the effect failed; " +
			"consumption and effect did not commit together")
	}
}

func failedEffectWrite(t TB, h Harness) {
	s, ctx := h.NewStore(t), context.Background()
	r := rec("cred-fail-write")
	// Write first, then fail. Both must roll back.
	err := s.Consume(ctx, r, func(ctx context.Context) error {
		if err := h.Write(ctx, r.ID); err != nil {
			return err
		}
		return errEffectFailed
	})
	if !errors.Is(err, errEffectFailed) {
		t.Fatalf("Consume returned %v, want the effect's error", err)
	}
	if h.Committed(t, r.ID) {
		t.Fatal("the effect's own write survived a failed effect; it is not running " +
			"inside the transaction that Consume opened")
	}
	if h.Consumed(t, r.ID) {
		t.Fatal("the credential was spent despite the failure")
	}
}

func retryAfterFailure(t TB, h Harness) {
	s, ctx := h.NewStore(t), context.Background()
	r := rec("cred-retry")
	_ = s.Consume(ctx, r, func(ctx context.Context) error { return errEffectFailed })

	if err := s.Consume(ctx, r, func(ctx context.Context) error {
		return h.Write(ctx, r.ID)
	}); err != nil {
		t.Fatalf("retrying after a failed effect returned %v; the customer would be "+
			"asked to authorise a payment they already approved", err)
	}
	if !h.Committed(t, r.ID) || !h.Consumed(t, r.ID) {
		t.Error("the retry did not complete")
	}
}

// The failure that quiet testing never finds. Two requests present the same
// credential at the same instant; both pass a check-then-act; both post.
//
// Simply starting N goroutines is not enough, and this check originally did
// exactly that: against a store that releases its lock across the effect, the
// scheduler serialised the attempts often enough that the double spend went
// undetected in roughly one run in five. A check that catches a defect four
// times out of five lets a broken store pass by luck, which is worse than not
// having the check — it produces a conformance result nobody should rely on.
//
// So the effect holds a barrier: each attempt that reaches it waits until every
// attempt has, or until a short timeout. A store that spends the credential
// before running the effect admits exactly one goroutine, which waits out the
// timeout alone and proceeds — costing one timeout per run and nothing else. A
// store that releases its lock admits all of them, the barrier opens
// immediately, and they overlap by construction rather than by chance.
func concurrent(t TB, h Harness) {
	s, ctx := h.NewStore(t), context.Background()
	r := rec("cred-race")

	const attempts = 16
	const barrierWait = 200 * time.Millisecond

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		inEffect int
		ok       int
		replay   int
		other    []error
		barrier  = make(chan struct{})
	)

	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			err := s.Consume(ctx, r, func(ctx context.Context) error {
				mu.Lock()
				inEffect++
				last := inEffect == attempts
				mu.Unlock()
				if last {
					close(barrier)
				}
				select {
				case <-barrier:
				case <-time.After(barrierWait):
				}
				return h.Write(ctx, fmt.Sprintf("%s-%d", r.ID, i))
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, boundedauth.ErrAlreadyConsumed):
				replay++
			default:
				other = append(other, err)
			}
		}(i)
	}
	wg.Wait()

	mu.Lock()
	entered := inEffect
	mu.Unlock()

	if entered > 1 {
		t.Errorf("%d of %d simultaneous attempts entered the effect at once; the "+
			"credential is not held for the duration of the work it authorises",
			entered, attempts)
	}
	if ok != 1 {
		t.Fatalf("%d of %d simultaneous presentations of one credential succeeded; "+
			"exactly 1 may", ok, attempts)
	}
	// The rest must be refused as replays, not lost to some other error. A
	// store that returns a lock timeout has not refused the replay; it has
	// failed, and a caller that retries will succeed.
	if replay != attempts-1 {
		t.Errorf("%d of %d losing attempts were refused as replays; the others returned %v",
			replay, attempts-1, other)
	}

	committed := 0
	for i := 0; i < attempts; i++ {
		if h.Committed(t, fmt.Sprintf("%s-%d", r.ID, i)) {
			committed++
		}
	}
	if committed != 1 {
		t.Fatalf("%d effects are durable after one credential was presented %d times "+
			"concurrently; exactly 1 may be", committed, attempts)
	}
}

func effectOnce(t TB, h Harness) {
	s, ctx := h.NewStore(t), context.Background()
	r := rec("cred-once")
	calls := 0
	if err := s.Consume(ctx, r, func(ctx context.Context) error {
		calls++
		return h.Write(ctx, r.ID)
	}); err != nil {
		t.Fatalf("consumption failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("the effect ran %d times; a store that retries the effect internally "+
			"can post the same payment twice", calls)
	}
}
