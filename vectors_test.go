package boundedauth_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

// Test vectors exist so an implementation in another language can prove it
// agrees with this one, rather than assert it.
//
// A specification without vectors is an invitation to diverge: two teams read
// the same prose about length-prefixed hashing, implement it differently, and
// discover the difference when a credential minted by one is refused by the
// other — or, far worse, accepted for the wrong transaction. The digests below
// pin the exact bytes.
//
// The signing key is a fixed seed and is published in this file. It is a test
// key. It must never appear in a deployment, which is why it is a visible
// constant rather than something loaded from an environment variable where it
// could be mistaken for configuration.
const testSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

type vectorFile struct {
	Note       string          `json:"note"`
	Version    string          `json:"version"`
	SeedHex    string          `json:"signingKeySeedHex"`
	PublicHex  string          `json:"publicKeyHex"`
	Bindings   []bindingVector `json:"bindings"`
	Credential credVector      `json:"credential"`
	Receipt    receiptVector   `json:"receipt"`
}

type bindingVector struct {
	Name    string         `json:"name"`
	Binding map[string]any `json:"binding"`
	Digest  string         `json:"digest"`
}

type credVector struct {
	Payload    boundedauth.Payload `json:"payload"`
	Credential string              `json:"credential"`
}

type receiptVector struct {
	Receipt     boundedauth.Receipt `json:"receipt"`
	ContentHash string              `json:"contentHash"`
}

func bindingVectors() []struct {
	name string
	b    boundedauth.Binding
} {
	return []struct {
		name string
		b    boundedauth.Binding
	}{
		{"empty", boundedauth.Binding{}},
		{"typical", boundedauth.Binding{
			Payer: "wallet:alice", Payee: "wallet:bob",
			AmountMinor: 50_000, FeeMinor: 250, Currency: "GHS", Reference: "txn-0001",
		}},
		// The pair that collides without length prefixing.
		{"boundary-a", boundedauth.Binding{Payer: "alice", Payee: "bob", Currency: "GHS", Reference: "r"}},
		{"boundary-b", boundedauth.Binding{Payer: "ali", Payee: "cebob", Currency: "GHS", Reference: "r"}},
		{"zero-fee", boundedauth.Binding{
			Payer: "a", Payee: "b", AmountMinor: 1, Currency: "GHS", Reference: "r",
		}},
		// Non-ASCII, to pin encoding rather than leave it to be discovered.
		{"unicode", boundedauth.Binding{
			Payer: "wallet:Ámà", Payee: "wallet:Ọ̀bí", AmountMinor: 100, Currency: "GHS", Reference: "ref-é",
		}},
		{"with-context", boundedauth.Binding{
			Payer: "a", Payee: "b", AmountMinor: 100, Currency: "GHS", Reference: "r",
			Context: []byte(`{"mandate":"m-1"}`),
		}},
		{"max-amount", boundedauth.Binding{
			Payer: "a", Payee: "b", AmountMinor: 9_223_372_036_854_775_807, Currency: "GHS", Reference: "r",
		}},
		// A negative amount and fee, so a cross-language implementation that
		// mishandles two's-complement (sign-extends into a wider field, or treats
		// the value as unsigned) cannot reproduce the vector by luck.
		{"negative-amount", boundedauth.Binding{
			Payer: "a", Payee: "b", AmountMinor: -9_223_372_036_854_775_808, FeeMinor: -1,
			Currency: "GHS", Reference: "r",
		}},
	}
}

func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	iss := boundedauth.Issuer{Name: "issuer.example", Key: key}

	v := vectorFile{
		Note: "Test vectors for bounded-authority. The signing key is a published " +
			"test key and must never be used in a deployment. An implementation in " +
			"another language agrees with this one when it reproduces every digest, " +
			"the credential string, and the receipt content hash.",
		Version:   boundedauth.Version,
		SeedHex:   testSeedHex,
		PublicHex: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
	}

	for _, bv := range bindingVectors() {
		v.Bindings = append(v.Bindings, bindingVector{
			Name: bv.name,
			Binding: map[string]any{
				"payer": bv.b.Payer, "payee": bv.b.Payee,
				"amountMinor": bv.b.AmountMinor, "feeMinor": bv.b.FeeMinor,
				"currency": bv.b.Currency, "reference": bv.b.Reference,
				"context": string(bv.b.Context),
			},
			Digest: bv.b.Digest(),
		})
	}

	b := bindingVectors()[1].b
	payload := boundedauth.Payload{
		ID: "cred-vector-1", Subject: "user:alice", Method: boundedauth.MethodPasskey,
		Binding: b.Digest(), IssuedAt: 1_700_000_000, ExpiresAt: 1_700_000_120,
	}
	cred, err := iss.Mint(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.Version, payload.Issuer = boundedauth.Version, iss.Name
	v.Credential = credVector{Payload: payload, Credential: cred}

	r := boundedauth.Receipt{
		ID: "rcpt-vector-1", Reference: b.Reference,
		IssuedAt: time.Unix(1_700_000_001, 0).UTC(), EffectID: "je-vector-1",
		Payer: b.Payer, Payee: b.Payee, AmountMinor: b.AmountMinor, FeeMinor: b.FeeMinor,
		Currency: b.Currency, Description: "Rent", GrantID: payload.ID,
		Method: boundedauth.MethodPasskey, Binding: b.Digest(),
	}.Issue()
	v.Receipt = receiptVector{Receipt: r, ContentHash: r.ContentHash}

	return v
}

// The format is a published interface. Changing any of these digests changes
// what a verifier accepts, so it must be a deliberate version change rather
// than a side effect of an edit — which is exactly what this test makes it.
func TestVectorsAreStable(t *testing.T) {
	got := buildVectors(t)
	path := filepath.Join("testdata", "vectors.json")

	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	if *update {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("vectors rewritten")
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; run: go test -run TestVectorsAreStable -update", err)
	}
	if string(want) != string(encoded) {
		t.Fatal("the vectors changed.\n\n" +
			"This is a wire-format change: credentials minted by this build will be " +
			"refused by verifiers built from the published vectors, and vice versa.\n" +
			"If it is deliberate, change Version and rerun with -update.\n" +
			"If it is not, something altered how a transaction is bound.")
	}
}

// The published credential must verify with the published key, so a reader can
// check the vectors are internally consistent before trusting them.
func TestPublishedCredentialVerifies(t *testing.T) {
	v := buildVectors(t)
	pub, err := hex.DecodeString(v.PublicHex)
	if err != nil {
		t.Fatal(err)
	}
	ver := boundedauth.Verifier{
		TrustedIssuers: map[string]ed25519.PublicKey{"issuer.example": pub},
		Now:            func() time.Time { return time.Unix(1_700_000_060, 0).UTC() },
	}
	b := bindingVectors()[1].b
	if _, err := ver.Verify(v.Credential.Credential, b); err != nil {
		t.Fatalf("the published credential does not verify: %v", err)
	}
	if !v.Receipt.Receipt.Intact() || !v.Receipt.Receipt.MatchesAuthority(b) {
		t.Fatal("the published receipt is not internally consistent")
	}
}
