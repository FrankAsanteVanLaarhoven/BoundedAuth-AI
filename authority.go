// Package boundedauth implements bounded authority for money movement: a
// signed, transaction-bound, single-use credential, and a receipt bound to the
// effect it authorised.
//
// # The problem this solves
//
// The usual way to authorise a payment is a token: the caller presents a string,
// the server checks that it is valid, and the payment proceeds. The token says
// who the caller is. It does not say what they agreed to. Anything holding a
// valid token can move any amount to any recipient within its scope, as often as
// it likes, and nothing in the credential itself contradicts that.
//
// That was tolerable when the caller was a person clicking a button. It is not
// tolerable when the caller is an automated agent composing payment requests
// from text it was given, because the interesting question stops being "is this
// caller authenticated" and becomes "did a human agree to THIS payment".
//
// A bounded authority answers the second question. It is a signature over the
// exact transaction — payer, payee, amount, fee, currency, transfer — so a
// credential obtained for one payment cannot be presented for another. It is
// spent once, atomically with the money it authorises. And it produces a receipt
// bound to the same digest, so the proof of what was authorised and the proof of
// what happened are the same chain of evidence.
//
// The consequence worth stating plainly: a compromised backend, a
// prompt-injected agent, or a hostile intermediary cannot obtain authority for a
// payment the human did not see. The worst any of them achieves is the payment
// that was actually signed.
//
// # What this package does not do
//
// It does not authenticate anyone. It verifies a credential minted by an issuer
// you trust. Producing that credential — WebAuthn, HSM, whatever binds a human
// to a key — is the issuer's job, and this package is deliberately indifferent
// to it beyond recording which method was used.
//
// It does not store anything. Single use requires durable state and, more
// importantly, requires that state to commit in the same transaction as the
// effect. Only the host knows how to do that, so the host implements [Store] and
// this package supplies a conformance suite that checks they got it right.
//
// # Wire format
//
//	base64url(payload JSON) "." base64url(ed25519 signature)
//
// The signature covers the encoded payload bytes exactly as transmitted, so
// verification never re-serialises and there is no canonicalisation ambiguity.
package boundedauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"
)

const (
	// Version is carried in every payload so the format can change without
	// ambiguity about what a verifier is looking at. A verifier rejects any
	// version it does not implement rather than attempting a best effort:
	// guessing at the meaning of a credential is how a downgrade becomes an
	// authorisation.
	Version = "bounded-authority/1"

	// MaxLifetime bounds how long a credential remains usable regardless of
	// what the issuer asked for.
	//
	// This is a ceiling, not a default, and it is enforced at mint AND at
	// verify. Enforcing it only at mint trusts the issuer to be neither
	// compromised nor misconfigured, which is the assumption this whole
	// package exists to avoid. A credential authorises one transaction a human
	// has just confirmed; it is not a session, and anything that lives long
	// enough to be stored, logged and later found is being used as one.
	MaxLifetime = 5 * time.Minute

	// MaxClockSkew tolerates modest drift between issuer and verifier.
	MaxClockSkew = 30 * time.Second
)

// Method records how the human actually authorised, carried inside the signed
// payload and copied into evidence.
//
// It exists so a reviewer can tell a real authenticator from a test one by
// reading a record, rather than by reconstructing what configuration was live
// at the time. A system where the strength of an authorisation is only knowable
// from deployment state cannot answer that question after an incident, which is
// exactly when it is asked.
type Method string

const (
	// MethodPasskey is a verified WebAuthn assertion from a device-bound
	// credential, where the challenge was the binding digest.
	MethodPasskey Method = "passkey"

	// MethodHardwareToken is an assertion from a dedicated signing device.
	MethodHardwareToken Method = "hardware_token"

	// MethodDelegatedMandate is a credential minted under a pre-authorised
	// mandate rather than a live human confirmation — a standing instruction,
	// a subscription, an agent operating inside limits a human set earlier.
	//
	// It is a genuinely weaker assertion than the others and is named so that
	// it cannot be mistaken for one of them in evidence.
	MethodDelegatedMandate Method = "delegated_mandate"

	// MethodTest is a credential minted with no authenticator challenge at all.
	// Verifiers refuse it unless explicitly configured to allow it, and it is
	// named so that a test authorisation can never be presented to a customer
	// or an auditor as a real one.
	MethodTest Method = "test_authenticator"
)

// knownMethods is the closed set of methods. An unknown value is refused at both
// mint and verify: the method is evidence a reviewer relies on, so it cannot be
// an arbitrary string, and a closed set is what makes the test-method gate
// robust — "test_authenticator " with a trailing space, or a novel value, is not
// a "valid non-test method", it is simply not a method.
var knownMethods = map[Method]bool{
	MethodPasskey:          true,
	MethodHardwareToken:    true,
	MethodDelegatedMandate: true,
	MethodTest:             true,
}

// Binding is the exact transaction a credential authorises. Every field that
// determines where money goes is covered; changing any of them invalidates the
// credential.
type Binding struct {
	// Payer and Payee are opaque to this package. They are whatever reference
	// the host's ledger uses, and are compared byte for byte.
	Payer string
	Payee string

	AmountMinor int64
	FeeMinor    int64

	// Currency is compared exactly. Callers should normalise case before
	// binding; "GHS" and "ghs" are different transactions here, deliberately,
	// because a verifier that normalises has to agree with an issuer that
	// normalises, and the two drifting apart is a silent authorisation bug.
	Currency string

	// Reference identifies the transaction being authorised, and is what makes
	// the credential single-use in practice: the same digest cannot be reused
	// for a second payment without reusing the reference.
	Reference string

	// Context is optional additional material bound into the digest — a
	// mandate identifier, a policy version, an agent identity. It lets a host
	// bind facts this package does not model without forking the format.
	Context []byte
}

// Digest is a length-prefixed hash, so no rearrangement of adjacent field values
// produces the same digest. Without length prefixing, a payment from "alice" to
// "bob" and one from "ali" to "cebob" would hash identically, and a credential
// for one would authorise the other.
func (b Binding) Digest() string {
	h := sha256.New()
	writeField(h, []byte(Version))
	writeField(h, []byte(b.Payer))
	writeField(h, []byte(b.Payee))
	writeInt(h, b.AmountMinor)
	writeInt(h, b.FeeMinor)
	writeField(h, []byte(b.Currency))
	writeField(h, []byte(b.Reference))
	writeField(h, b.Context)
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

func writeInt(h hash.Hash, v int64) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(v))
	_, _ = h.Write(n[:])
}

// Payload is the signed content of a credential.
type Payload struct {
	Version   string `json:"v"`
	ID        string `json:"jti"`
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Method    Method `json:"method"`
	Binding   string `json:"binding"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// Issuer mints credentials. Only the party that has authenticated the human
// holds a private key.
type Issuer struct {
	// Name identifies this issuer to verifiers. It is carried in the payload
	// and checked, so a credential from an unexpected issuer is refused even
	// when its signature is valid under some key the verifier holds.
	Name string
	Key  ed25519.PrivateKey
}

// Mint signs a payload.
//
// The lifetime ceiling is applied here as well as at verification. Both ends
// enforce it because either end can be the one that is wrong.
func (i Issuer) Mint(p Payload) (string, error) {
	if len(i.Key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: private key wrong size", ErrMalformed)
	}
	if i.Name == "" {
		return "", fmt.Errorf("%w: issuer name is required", ErrMalformed)
	}
	p.Version, p.Issuer = Version, i.Name
	if p.ID == "" || p.Subject == "" || p.Binding == "" {
		return "", fmt.Errorf("%w: jti, sub and binding are required", ErrMalformed)
	}
	if p.Method == "" {
		return "", fmt.Errorf("%w: method is required; an authorisation whose "+
			"strength is unrecorded cannot be assessed later", ErrMalformed)
	}
	if !knownMethods[p.Method] {
		return "", fmt.Errorf("%w: unknown method %q", ErrMalformed, p.Method)
	}
	if p.ExpiresAt <= p.IssuedAt {
		return "", fmt.Errorf("%w: expiry must be after issuance", ErrMalformed)
	}
	if p.ExpiresAt-p.IssuedAt > int64(MaxLifetime.Seconds()) {
		return "", ErrLifetimeTooLong
	}

	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(i.Key, []byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verifier checks credentials. It is a value rather than a package-level
// function because the set of trusted issuers is a deployment decision, and a
// package that hardcodes one issuer cannot be used by anyone else — which was
// true of the implementation this was extracted from.
type Verifier struct {
	// TrustedIssuers maps issuer name to public key. A credential is checked
	// against the key for the issuer it names, so adding a second issuer does
	// not widen what the first one can authorise.
	TrustedIssuers map[string]ed25519.PublicKey

	// AllowTestMethod permits [MethodTest]. It defaults to false, so a
	// deployment that forgets to configure anything refuses test credentials
	// rather than accepting them. The failure of omission should be a refusal.
	AllowTestMethod bool

	// Now is injectable for testing. Nil means time.Now.
	Now func() time.Time
}

func (v Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks the signature, the issuer, the version, the validity window,
// the method and the transaction binding.
//
// It does NOT check single use. That requires durable state committed with the
// effect, which only the host can do — see [Store] and [Authorise]. A caller
// that uses Verify alone has a credential that is unforgeable and correctly
// bound, and infinitely replayable.
func (v Verifier) Verify(credential string, want Binding) (Payload, error) {
	encoded, sigPart, ok := strings.Cut(credential, ".")
	if !ok || encoded == "" || sigPart == "" {
		return Payload{}, fmt.Errorf("%w: expected payload.signature", ErrMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: signature is not base64url", ErrMalformed)
	}

	// The payload is read twice: once untrusted, to learn which issuer key to
	// check against, and again only after that signature verifies. Nothing
	// from the first read reaches a decision.
	claimed, err := ParseUnverified(credential)
	if err != nil {
		return Payload{}, err
	}
	pub, known := v.TrustedIssuers[claimed.Issuer]
	if !known {
		return Payload{}, fmt.Errorf("%w: %q", ErrUntrustedIssuer, claimed.Issuer)
	}
	if len(pub) != ed25519.PublicKeySize {
		return Payload{}, fmt.Errorf("%w: public key for %q wrong size", ErrMalformed, claimed.Issuer)
	}
	if !ed25519.Verify(pub, []byte(encoded), sig) {
		return Payload{}, ErrBadSignature
	}

	// Re-decode strictly from the bytes that just verified.
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	var p Payload
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	if p.Version != Version {
		return Payload{}, fmt.Errorf("%w: %q", ErrWrongVersion, p.Version)
	}
	if p.Issuer != claimed.Issuer {
		// Unreachable through the signature check, but asserted rather than
		// assumed: the whole design rests on the verified payload being the
		// one whose issuer selected the key.
		return Payload{}, fmt.Errorf("%w: issuer changed between reads", ErrMalformed)
	}
	if p.ID == "" {
		return Payload{}, fmt.Errorf("%w: jti is required, and without it the "+
			"credential cannot be spent exactly once", ErrMalformed)
	}
	// The method must be one of the closed set. Checking this before the
	// test-method gate is what stops a near-miss ("test_authenticator " with a
	// trailing space, or any novel string) slipping through as a "valid non-test
	// method": an unknown method is refused outright, not treated as real. The
	// verifier does not trust the issuer to have configured the method well, for
	// the same reason it re-checks the lifetime ceiling below.
	if !knownMethods[p.Method] {
		return Payload{}, fmt.Errorf("%w: unknown method %q", ErrMalformed, p.Method)
	}
	if p.Method == MethodTest && !v.AllowTestMethod {
		return Payload{}, ErrTestMethodRefused
	}
	// Enforced at verify as well as at mint, because either end can be the one
	// that is compromised. A credential that expires before it was issued is
	// nonsensical and refused.
	if p.ExpiresAt <= p.IssuedAt {
		return Payload{}, fmt.Errorf("%w: expiry must be after issuance", ErrMalformed)
	}
	if p.ExpiresAt-p.IssuedAt > int64(MaxLifetime.Seconds()) {
		return Payload{}, ErrLifetimeTooLong
	}

	now := v.now()
	if now.Add(MaxClockSkew).Unix() < p.IssuedAt {
		return Payload{}, ErrNotYetValid
	}
	if now.Add(-MaxClockSkew).Unix() > p.ExpiresAt {
		return Payload{}, ErrExpired
	}
	if p.Binding != want.Digest() {
		return Payload{}, ErrBindingMismatch
	}
	return p, nil
}

// ParseUnverified decodes a credential WITHOUT checking its signature.
//
// It exists so a service that is not the authority can fail fast — an
// orchestrator refusing to start work for a credential that names a different
// transaction, say. Nothing it returns is trustworthy. Never make an
// authorisation decision on this.
func ParseUnverified(credential string) (Payload, error) {
	encoded, _, ok := strings.Cut(credential, ".")
	if !ok || encoded == "" {
		return Payload{}, fmt.Errorf("%w: expected payload.signature", ErrMalformed)
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return p, nil
}
