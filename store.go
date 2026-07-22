package boundedauth

import (
	"context"
	"time"
)

// Store is the durable half of single use, implemented by the host.
//
// # Why this is an interface and not an implementation
//
// Spending a credential exactly once is easy to get wrong in a way that tests
// do not catch. The tempting implementation is a check: look the identifier up,
// see that it is unused, mark it used, do the work. Under concurrency two
// callers pass the check before either writes. Under partial failure the
// credential is marked used and the payment never happens, so a customer who
// was charged nothing must re-authorise something they already approved — or,
// worse, the payment happens and the mark is lost, and the credential works
// again.
//
// The only implementation that is correct is one where spending the credential
// and performing the effect commit together. That is a property of the host's
// transaction boundary, not of this package, so this package cannot provide it.
// What it provides instead is a shape that makes the correct implementation the
// natural one, and a conformance suite that fails the incorrect ones.
//
// # The contract
//
// Consume must, atomically:
//
//  1. Record rec as consumed, failing with [ErrAlreadyConsumed] if its ID has
//     been recorded before.
//  2. Call effect exactly once, inside the same transaction.
//  3. Commit both, or neither.
//
// If effect returns an error, the consumption must not be durable: the
// credential is still spendable afterwards. This is the requirement most
// implementations miss, and the one the conformance suite checks hardest.
//
// Implementations must be safe for concurrent use. Exactly one of N
// simultaneous attempts on the same ID may succeed.
type Store interface {
	Consume(ctx context.Context, rec Consumption, effect func(context.Context) error) error
}

// Consumption is the durable record that a credential was spent, and on what.
//
// It records the binding digest as well as the identifier, so a spent
// credential can be tied back to the transaction it authorised without
// re-deriving it from the credential — which may no longer exist, and should
// not be retained, since a stored credential is a stored authorisation.
type Consumption struct {
	ID         string
	Issuer     string
	Subject    string
	Method     Method
	Binding    string
	Reference  string
	ConsumedAt time.Time
}

// Authorise is the whole point of the package: verify a credential against the
// exact transaction, then spend it atomically with the effect it authorises.
//
// The effect runs inside the host's transaction. It receives the verified
// payload's consumption record so that whatever it writes — postings, a
// receipt, an evidence row — can cite the authority that permitted it, in the
// same commit. Nothing else in the system should be able to produce that
// effect, because nothing else can produce that citation.
//
// The ordering is deliberate and is the security property: verification of the
// binding happens before consumption, so a credential presented for the wrong
// transaction is refused without being spent. A caller cannot burn someone
// else's authority by presenting it against a transaction they control.
func Authorise(
	ctx context.Context,
	v Verifier,
	store Store,
	credential string,
	want Binding,
	effect func(context.Context, Consumption) error,
) (Consumption, error) {
	p, err := v.Verify(credential, want)
	if err != nil {
		return Consumption{}, err
	}
	rec := Consumption{
		ID: p.ID, Issuer: p.Issuer, Subject: p.Subject, Method: p.Method,
		Binding: p.Binding, Reference: want.Reference, ConsumedAt: v.now(),
	}
	if err := store.Consume(ctx, rec, func(ctx context.Context) error {
		return effect(ctx, rec)
	}); err != nil {
		return Consumption{}, err
	}
	return rec, nil
}
