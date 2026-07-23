package boundedauth

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// The credential is a string handed to the authority by an untrusted caller —
// an agent, a front end, a partner. Parsing it must never panic: a panic on the
// verification path is a denial of service on the money path, tripped by input
// an attacker fully controls. These fuzz targets assert the parse/verify path
// terminates on arbitrary input, and that nothing malformed is ever mistaken for
// a valid, verified credential.

var fuzzSeeds = []string{
	"",
	".",
	"a.b",
	"a.",
	".b",
	"AAAA.BBBB",
	"not base64!.@@@@",
	"eyJ2IjoiMSJ9.QQ",
	"eyJ2IjoiYm91bmRlZGF1dGgvMSJ9.",
	"...",
	"\x00.\x00",
}

// FuzzParseUnverified: the fail-fast parser must terminate on any input, and a
// successful parse must be deterministic — it carries no hidden state.
func FuzzParseUnverified(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, credential string) {
		p, err := ParseUnverified(credential)
		if err != nil {
			return
		}
		p2, err2 := ParseUnverified(credential)
		if err2 != nil || p2 != p {
			t.Fatalf("ParseUnverified is not deterministic for %q", credential)
		}
	})
}

// FuzzVerify: verification must terminate on any input, and if it ever returns
// no error, the returned payload must satisfy every invariant Verify claims to
// enforce. A random string cannot forge an Ed25519 signature, so in practice
// every case errors — the value is proving the whole base64 → JSON → checks path
// never panics, and that "no error" can never coexist with a broken invariant.
func FuzzVerify(f *testing.F) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	v := Verifier{
		TrustedIssuers: map[string]ed25519.PublicKey{"acme": pub},
		Now:            func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	want := Binding{
		Payer: "wallet:a", Payee: "wallet:b",
		AmountMinor: 100, FeeMinor: 1, Currency: "GHS", Reference: "r1",
	}

	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, credential string) {
		p, err := v.Verify(credential, want)
		if err != nil {
			return
		}
		// Reached only if a fuzzed string verified. Every checked property must
		// still hold — otherwise "verified" would mean less than it claims.
		if p.Version != Version {
			t.Fatalf("verified with wrong version %q", p.Version)
		}
		if !knownMethods[p.Method] {
			t.Fatalf("verified with unknown method %q", p.Method)
		}
		if p.ID == "" {
			t.Fatalf("verified with empty jti")
		}
		if p.ExpiresAt <= p.IssuedAt {
			t.Fatalf("verified with expiry <= issuance")
		}
		if p.Binding != want.Digest() {
			t.Fatalf("verified with mismatched binding")
		}
	})
}
