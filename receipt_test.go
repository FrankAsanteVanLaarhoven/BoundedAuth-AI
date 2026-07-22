package boundedauth_test

import (
	"testing"
	"time"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
)

func receipt() boundedauth.Receipt {
	return boundedauth.Receipt{
		ID: "rcpt-1", Reference: "txn-0001", IssuedAt: at, EffectID: "je-77",
		Payer: "wallet:alice", Payee: "wallet:bob",
		AmountMinor: 50_000, FeeMinor: 250, Currency: "GHS",
		Description: "Rent", GrantID: "cred-1",
		Method: boundedauth.MethodPasskey, Binding: binding().Digest(),
	}.Issue()
}

func TestReceiptVerifiesAgainstItsOwnHash(t *testing.T) {
	if !receipt().Intact() {
		t.Fatal("a freshly issued receipt did not verify against its own hash")
	}
}

func TestAlteringAnyFieldBreaksTheReceipt(t *testing.T) {
	for name, mutate := range map[string]func(*boundedauth.Receipt){
		"amount":      func(r *boundedauth.Receipt) { r.AmountMinor = 5 },
		"fee":         func(r *boundedauth.Receipt) { r.FeeMinor = 0 },
		"payee":       func(r *boundedauth.Receipt) { r.Payee = "wallet:mallory" },
		"currency":    func(r *boundedauth.Receipt) { r.Currency = "NGN" },
		"description": func(r *boundedauth.Receipt) { r.Description = "Groceries" },
		"grant":       func(r *boundedauth.Receipt) { r.GrantID = "cred-9" },
		"method":      func(r *boundedauth.Receipt) { r.Method = boundedauth.MethodTest },
		"effect":      func(r *boundedauth.Receipt) { r.EffectID = "je-99" },
		"issued at":   func(r *boundedauth.Receipt) { r.IssuedAt = at.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			r := receipt()
			mutate(&r)
			if r.Intact() {
				t.Fatalf("changing the %s left the receipt verifying", name)
			}
		})
	}
}

// The hash must survive a round trip through storage. Most databases keep
// timestamps to microseconds, so a hash over a nanosecond value verifies in
// memory and fails once stored — which is a bug the implementation this was
// extracted from shipped, and the reason Issue truncates.
func TestHashSurvivesMicrosecondStorage(t *testing.T) {
	r := boundedauth.Receipt{
		ID: "rcpt-2", Reference: "txn-2", IssuedAt: time.Unix(0, 1_700_000_000_123_456_789).UTC(),
		Payer: "a", Payee: "b", AmountMinor: 1, Currency: "GHS",
		GrantID: "c", Method: boundedauth.MethodPasskey, Binding: binding().Digest(),
	}.Issue()

	stored := r
	stored.IssuedAt = r.IssuedAt.Truncate(time.Microsecond) // what a database returns
	if !stored.Intact() {
		t.Fatal("the receipt stopped verifying after a microsecond-resolution round trip")
	}
}

// A receipt can be unaltered since issue and still describe a different payment
// from the one that was authorised, if the code that issued it was wrong.
// Intactness proves nobody edited it; this proves it was right when written.
func TestReceiptIsCheckedAgainstTheAuthorityNotOnlyItself(t *testing.T) {
	r := receipt()
	if !r.MatchesAuthority(binding()) {
		t.Fatal("a receipt issued for this transaction did not match its authority")
	}

	other := binding()
	other.AmountMinor = 999_999
	if r.MatchesAuthority(other) {
		t.Fatal("a receipt matched an authority for a different amount")
	}

	// The dangerous case: a receipt that is internally consistent — correctly
	// hashed, nothing edited — but was issued against the wrong authority.
	wrong := receipt()
	wrong.Binding = other.Digest()
	wrong = wrong.Issue()
	if !wrong.Intact() {
		t.Fatal("precondition: the receipt should be internally consistent")
	}
	if wrong.MatchesAuthority(binding()) {
		t.Fatal("an intact receipt issued against the wrong authority was accepted; " +
			"intactness was mistaken for correctness")
	}
}

func TestUnissuedReceiptIsNotIntact(t *testing.T) {
	var r boundedauth.Receipt
	if r.Intact() {
		t.Fatal("a receipt with no content hash reported itself intact")
	}
	if r.MatchesAuthority(binding()) {
		t.Fatal("a receipt with no binding matched an authority")
	}
}

// The red-team finding: a receipt whose displayed fields describe a DIFFERENT
// payment than its binding must not pass MatchesAuthority, even though it is
// intact (its hash covers the wrong fields, so it is self-consistent). Before
// the fix, MatchesAuthority compared only the stored binding string and affirmed
// a receipt showing the wrong money.
func TestReceiptWithMismatchedFieldsFailsMatchesAuthority(t *testing.T) {
	authorised := binding() // the real transaction: alice -> bob, 50000

	// A receipt that CITES the real binding but DISPLAYS a different payment.
	forged := boundedauth.Receipt{
		ID: "rcpt-x", Reference: authorised.Reference, IssuedAt: at, EffectID: "je-x",
		Payer: "wallet:alice", Payee: "wallet:MALLORY", // wrong payee
		AmountMinor: 999_999, // wrong amount
		Currency:    "GHS", Description: "Rent", GrantID: "cred-1",
		Method:  boundedauth.MethodPasskey,
		Binding: authorised.Digest(), // but it carries the REAL binding digest
	}.Issue()

	// It is intact — nobody edited it since issue.
	if !forged.Intact() {
		t.Fatal("precondition: the receipt should be self-consistent (intact)")
	}
	// But it must NOT match the authority: its own fields do not reproduce the
	// binding it carries.
	if forged.MatchesAuthority(authorised) {
		t.Fatal("a receipt displaying a different payment matched the authority")
	}
}

// A receipt whose fields DO reproduce a context-bearing binding matches; one
// that drops the context does not. Without the Context field this was impossible.
func TestReceiptMatchesAContextBinding(t *testing.T) {
	b := binding()
	b.Context = []byte(`{"mandate":"m-7"}`)

	good := boundedauth.Receipt{
		ID: "rcpt-c", Reference: b.Reference, IssuedAt: at, EffectID: "je-c",
		Payer: b.Payer, Payee: b.Payee, AmountMinor: b.AmountMinor, FeeMinor: b.FeeMinor,
		Currency: b.Currency, Description: "Rent", GrantID: "cred-1",
		Method: boundedauth.MethodPasskey, Binding: b.Digest(),
		Context: b.Context,
	}.Issue()
	if !good.MatchesAuthority(b) {
		t.Fatal("a receipt carrying the binding's context did not match it")
	}

	// Drop the context: the receipt no longer reproduces the binding.
	noCtx := good
	noCtx.Context = nil
	noCtx = noCtx.Issue()
	if noCtx.MatchesAuthority(b) {
		t.Fatal("a receipt that dropped the binding context still matched it")
	}
}
