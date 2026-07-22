package boundedauth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI/memory"
)

var at = time.Unix(1_700_000_000, 0).UTC()

func testIssuer(t *testing.T) (boundedauth.Issuer, boundedauth.Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	iss := boundedauth.Issuer{Name: "issuer.test", Key: priv}
	ver := boundedauth.Verifier{
		TrustedIssuers: map[string]ed25519.PublicKey{"issuer.test": pub},
		Now:            func() time.Time { return at },
	}
	return iss, ver
}

func binding() boundedauth.Binding {
	return boundedauth.Binding{
		Payer: "wallet:alice", Payee: "wallet:bob",
		AmountMinor: 50_000, FeeMinor: 250, Currency: "GHS",
		Reference: "txn-0001",
	}
}

func mint(t *testing.T, iss boundedauth.Issuer, b boundedauth.Binding) string {
	t.Helper()
	c, err := iss.Mint(boundedauth.Payload{
		ID: "cred-1", Subject: "user:alice", Method: boundedauth.MethodPasskey,
		Binding: b.Digest(), IssuedAt: at.Unix(), ExpiresAt: at.Add(2 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return c
}

// --- binding ---

// Without length prefixing, a payment from "alice" to "bob" and one from "ali"
// to "cebob" hash identically, and a credential for one authorises the other.
func TestDigestIsUnambiguousAcrossFieldBoundaries(t *testing.T) {
	a := boundedauth.Binding{Payer: "alice", Payee: "bob", Currency: "GHS", Reference: "r"}
	b := boundedauth.Binding{Payer: "ali", Payee: "cebob", Currency: "GHS", Reference: "r"}
	if a.Digest() == b.Digest() {
		t.Fatal("two different transactions produced the same digest")
	}
}

func TestEveryBindingFieldChangesTheDigest(t *testing.T) {
	base := binding()
	for name, mutate := range map[string]func(*boundedauth.Binding){
		"payer":     func(b *boundedauth.Binding) { b.Payer = "wallet:mallory" },
		"payee":     func(b *boundedauth.Binding) { b.Payee = "wallet:mallory" },
		"amount":    func(b *boundedauth.Binding) { b.AmountMinor++ },
		"fee":       func(b *boundedauth.Binding) { b.FeeMinor++ },
		"currency":  func(b *boundedauth.Binding) { b.Currency = "NGN" },
		"reference": func(b *boundedauth.Binding) { b.Reference = "txn-0002" },
		"context":   func(b *boundedauth.Binding) { b.Context = []byte("mandate:7") },
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			if m.Digest() == base.Digest() {
				t.Fatalf("changing %s did not change the digest; a credential for one "+
					"transaction would authorise the other", name)
			}
		})
	}
}

// --- verification ---

func TestMintAndVerifyRoundTrip(t *testing.T) {
	iss, ver := testIssuer(t)
	p, err := ver.Verify(mint(t, iss, binding()), binding())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.Subject != "user:alice" || p.Method != boundedauth.MethodPasskey {
		t.Fatalf("payload lost fields: %+v", p)
	}
}

// The point of the whole design: a credential obtained for one payment cannot
// be presented for another.
func TestRepointingIsRefused(t *testing.T) {
	iss, ver := testIssuer(t)
	c := mint(t, iss, binding())

	for name, mutate := range map[string]func(*boundedauth.Binding){
		"a larger amount":       func(b *boundedauth.Binding) { b.AmountMinor = 500_000 },
		"a different recipient": func(b *boundedauth.Binding) { b.Payee = "wallet:mallory" },
		"a different currency":  func(b *boundedauth.Binding) { b.Currency = "NGN" },
		"a second transfer":     func(b *boundedauth.Binding) { b.Reference = "txn-0002" },
	} {
		t.Run(name, func(t *testing.T) {
			want := binding()
			mutate(&want)
			if _, err := ver.Verify(c, want); !errors.Is(err, boundedauth.ErrBindingMismatch) {
				t.Fatalf("presenting the credential for %s returned %v, want ErrBindingMismatch", name, err)
			}
		})
	}
}

func TestForgedSignatureIsRefused(t *testing.T) {
	iss, ver := testIssuer(t)
	c := mint(t, iss, binding())
	payload, _, _ := strings.Cut(c, ".")

	// A signature from a key the verifier does not trust.
	_, other, _ := ed25519.GenerateKey(nil)
	forged := payload + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(other, []byte(payload)))
	if _, err := ver.Verify(forged, binding()); !errors.Is(err, boundedauth.ErrBadSignature) {
		t.Fatalf("a forged signature returned %v", err)
	}
}

// An issuer the verifier does not know is refused even when the credential is
// internally valid. Trust is per-issuer, so adding one does not widen another.
func TestUntrustedIssuerIsRefused(t *testing.T) {
	_, ver := testIssuer(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	stranger := boundedauth.Issuer{Name: "issuer.evil", Key: priv}
	c, err := stranger.Mint(boundedauth.Payload{
		ID: "cred-x", Subject: "user:alice", Method: boundedauth.MethodPasskey,
		Binding: binding().Digest(), IssuedAt: at.Unix(), ExpiresAt: at.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(c, binding()); !errors.Is(err, boundedauth.ErrUntrustedIssuer) {
		t.Fatalf("a credential from an unknown issuer returned %v", err)
	}
}

// Tampering with the payload after signing must fail, including a change that
// leaves the JSON well formed.
func TestAlteredPayloadIsRefused(t *testing.T) {
	iss, ver := testIssuer(t)
	c := mint(t, iss, binding())
	encoded, sig, _ := strings.Cut(c, ".")
	body, _ := base64.RawURLEncoding.DecodeString(encoded)

	var p boundedauth.Payload
	_ = json.Unmarshal(body, &p)
	p.Subject = "user:mallory"
	altered, _ := json.Marshal(p)

	tampered := base64.RawURLEncoding.EncodeToString(altered) + "." + sig
	if _, err := ver.Verify(tampered, binding()); !errors.Is(err, boundedauth.ErrBadSignature) {
		t.Fatalf("an altered payload returned %v", err)
	}
}

func TestExpiryAndValidityWindow(t *testing.T) {
	iss, ver := testIssuer(t)
	c := mint(t, iss, binding())

	late := ver
	late.Now = func() time.Time { return at.Add(10 * time.Minute) }
	if _, err := late.Verify(c, binding()); !errors.Is(err, boundedauth.ErrExpired) {
		t.Fatalf("an expired credential returned %v", err)
	}

	early := ver
	early.Now = func() time.Time { return at.Add(-10 * time.Minute) }
	if _, err := early.Verify(c, binding()); !errors.Is(err, boundedauth.ErrNotYetValid) {
		t.Fatalf("a not-yet-valid credential returned %v", err)
	}
}

// The ceiling is enforced at both ends because either end can be the one that
// is wrong. This mints past the ceiling by signing directly, which is what a
// compromised or misconfigured issuer would effectively be doing.
func TestLifetimeCeilingIsEnforcedAtVerifyNotOnlyAtMint(t *testing.T) {
	iss, ver := testIssuer(t)

	if _, err := iss.Mint(boundedauth.Payload{
		ID: "cred-long", Subject: "user:alice", Method: boundedauth.MethodPasskey,
		Binding: binding().Digest(), IssuedAt: at.Unix(), ExpiresAt: at.Add(24 * time.Hour).Unix(),
	}); !errors.Is(err, boundedauth.ErrLifetimeTooLong) {
		t.Fatalf("minting a day-long credential returned %v", err)
	}

	body, _ := json.Marshal(boundedauth.Payload{
		Version: boundedauth.Version, ID: "cred-long", Issuer: "issuer.test",
		Subject: "user:alice", Method: boundedauth.MethodPasskey, Binding: binding().Digest(),
		IssuedAt: at.Unix(), ExpiresAt: at.Add(24 * time.Hour).Unix(),
	})
	encoded := base64.RawURLEncoding.EncodeToString(body)
	c := encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(iss.Key, []byte(encoded)))

	if _, err := ver.Verify(c, binding()); !errors.Is(err, boundedauth.ErrLifetimeTooLong) {
		t.Fatalf("a correctly signed day-long credential verified with %v; the "+
			"verifier is trusting the issuer to bound its own credentials", err)
	}
}

// A deployment that configures nothing refuses test credentials. The failure of
// omission should be a refusal.
func TestTestMethodIsRefusedByDefault(t *testing.T) {
	iss, ver := testIssuer(t)
	c, err := iss.Mint(boundedauth.Payload{
		ID: "cred-t", Subject: "user:alice", Method: boundedauth.MethodTest,
		Binding: binding().Digest(), IssuedAt: at.Unix(), ExpiresAt: at.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(c, binding()); !errors.Is(err, boundedauth.ErrTestMethodRefused) {
		t.Fatalf("a test credential verified by default: %v", err)
	}

	permissive := ver
	permissive.AllowTestMethod = true
	if _, err := permissive.Verify(c, binding()); err != nil {
		t.Fatalf("a test credential was refused where it is explicitly allowed: %v", err)
	}
}

// An unrecognised field means the credential was produced by something that
// believes the format has properties this verifier does not implement.
func TestUnknownFieldsAreRefused(t *testing.T) {
	iss, ver := testIssuer(t)
	body := []byte(`{"v":"` + boundedauth.Version + `","jti":"c","iss":"issuer.test",` +
		`"sub":"user:alice","method":"passkey","binding":"` + binding().Digest() + `",` +
		`"iat":` + strconv.FormatInt(at.Unix(), 10) + `,"exp":` + strconv.FormatInt(at.Add(time.Minute).Unix(), 10) + `,` +
		`"unlimited":true}`)
	encoded := base64.RawURLEncoding.EncodeToString(body)
	c := encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(iss.Key, []byte(encoded)))

	if _, err := ver.Verify(c, binding()); !errors.Is(err, boundedauth.ErrMalformed) {
		t.Fatalf("a credential carrying an unknown field verified with %v", err)
	}
}

// --- single use, end to end ---

func TestAuthoriseSpendsOnce(t *testing.T) {
	iss, ver := testIssuer(t)
	store := memory.New()
	c := mint(t, iss, binding())

	effect := func(ctx context.Context, rec boundedauth.Consumption) error {
		return store.Put(ctx, "posting:"+rec.Reference, []byte("posted"))
	}

	if _, err := boundedauth.Authorise(context.Background(), ver, store, c, binding(), effect); err != nil {
		t.Fatalf("first authorisation failed: %v", err)
	}
	_, err := boundedauth.Authorise(context.Background(), ver, store, c, binding(), effect)
	if !errors.Is(err, boundedauth.ErrAlreadyConsumed) {
		t.Fatalf("replay returned %v, want ErrAlreadyConsumed", err)
	}
}

// Presenting a credential against the wrong transaction must refuse it WITHOUT
// spending it. Otherwise anyone who observes a credential can burn it by
// presenting it against a transaction of their own choosing, and the customer's
// real payment fails.
func TestARepointedCredentialIsNotSpent(t *testing.T) {
	iss, ver := testIssuer(t)
	store := memory.New()
	c := mint(t, iss, binding())

	wrong := binding()
	wrong.AmountMinor = 999_999
	if _, err := boundedauth.Authorise(context.Background(), ver, store, c, wrong,
		func(context.Context, boundedauth.Consumption) error { return nil }); !errors.Is(err, boundedauth.ErrBindingMismatch) {
		t.Fatalf("got %v, want ErrBindingMismatch", err)
	}
	if _, spent := store.Consumption("cred-1"); spent {
		t.Fatal("a credential refused for the wrong transaction was spent anyway; " +
			"an observer could burn a customer's authorisation at will")
	}

	// And the genuine payment still works.
	if _, err := boundedauth.Authorise(context.Background(), ver, store, c, binding(),
		func(ctx context.Context, rec boundedauth.Consumption) error { return nil }); err != nil {
		t.Fatalf("the correct transaction failed after a repointing attempt: %v", err)
	}
}

// The consumption record the effect receives is the verified one, so whatever
// the effect writes can cite the authority that permitted it in the same commit.
func TestEffectReceivesTheVerifiedAuthority(t *testing.T) {
	iss, ver := testIssuer(t)
	store := memory.New()

	var got boundedauth.Consumption
	if _, err := boundedauth.Authorise(context.Background(), ver, store, mint(t, iss, binding()), binding(),
		func(ctx context.Context, rec boundedauth.Consumption) error {
			got = rec
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if got.ID != "cred-1" || got.Binding != binding().Digest() || got.Method != boundedauth.MethodPasskey {
		t.Fatalf("the effect received %+v", got)
	}
}

// The red-team finding: the verifier accepted arbitrary method strings, voiding
// the method's evidentiary purpose and letting a near-miss ("test_authenticator "
// with a trailing space) slip past the test-method gate as a "valid non-test
// method". The method is now a closed set, refused at both ends.
func TestUnknownMethodIsRefused(t *testing.T) {
	iss, ver := testIssuer(t)

	// Mint refuses an unknown method.
	if _, err := iss.Mint(boundedauth.Payload{
		ID: "cred-m", Subject: "user:alice", Method: "totally_made_up",
		Binding: binding().Digest(), IssuedAt: at.Unix(), ExpiresAt: at.Add(time.Minute).Unix(),
	}); !errors.Is(err, boundedauth.ErrMalformed) {
		t.Fatalf("mint accepted an unknown method: %v", err)
	}

	// A hand-signed credential with a near-miss of the test method is refused by
	// Verify — it is not "test_authenticator", so it cannot ride through as a
	// valid non-test method.
	for _, m := range []string{"test_authenticator ", "Test_Authenticator", "made_up"} {
		body, _ := json.Marshal(boundedauth.Payload{
			Version: boundedauth.Version, ID: "cred-m", Issuer: "issuer.test",
			Subject: "user:alice", Method: boundedauth.Method(m), Binding: binding().Digest(),
			IssuedAt: at.Unix(), ExpiresAt: at.Add(time.Minute).Unix(),
		})
		enc := base64.RawURLEncoding.EncodeToString(body)
		cred := enc + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(iss.Key, []byte(enc)))
		if _, err := ver.Verify(cred, binding()); !errors.Is(err, boundedauth.ErrMalformed) {
			t.Fatalf("verify accepted method %q: %v", m, err)
		}
	}
}

// A credential that expires at or before it was issued is refused at verify, not
// only at mint — both ends enforce the lifetime rules.
func TestZeroOrNegativeLifetimeIsRefusedAtVerify(t *testing.T) {
	iss, ver := testIssuer(t)
	for _, exp := range []int64{at.Unix(), at.Add(-time.Second).Unix()} {
		body, _ := json.Marshal(boundedauth.Payload{
			Version: boundedauth.Version, ID: "cred-z", Issuer: "issuer.test",
			Subject: "user:alice", Method: boundedauth.MethodPasskey, Binding: binding().Digest(),
			IssuedAt: at.Unix(), ExpiresAt: exp,
		})
		enc := base64.RawURLEncoding.EncodeToString(body)
		cred := enc + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(iss.Key, []byte(enc)))
		if _, err := ver.Verify(cred, binding()); !errors.Is(err, boundedauth.ErrMalformed) {
			t.Fatalf("verify accepted exp<=iat (exp=%d): %v", exp, err)
		}
	}
}
