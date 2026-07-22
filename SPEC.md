# Bounded Authority — specification

Version `bounded-authority/1`.

This document is normative. It is precise enough to implement from, and
[`testdata/vectors.json`](testdata/vectors.json) lets an implementation prove it
agrees rather than assert it. `testdata/verify_vectors.py` is an independent
implementation of the digest rules written from this document, kept in the
repository so the claim "this is implementable from the spec" is checkable.

The keywords MUST, MUST NOT, SHOULD and MAY are used in the usual sense.

---

## 1. What this specifies

A credential that authorises **one specific movement of money, once**.

It differs from a bearer token in that the signature covers the transaction
itself. A credential obtained for one payment cannot be presented for another,
by anyone, including the service that requested it. That property is what makes
it safe to let an untrusted or non-deterministic component — an agent, a
partner integration, a compromised front end — participate in composing a
payment request: the worst it can achieve is the payment a human actually
signed.

It also specifies a **receipt** bound to the same digest, so the proof of what
was authorised and the proof of what happened are one chain of evidence.

### 1.1 What it does not specify

- **How the human is authenticated.** WebAuthn, a hardware token, an HSM under
  a mandate — all are out of scope beyond recording which was used. The issuer
  is trusted to have done this.
- **Where anything is stored.** Single use requires durable state; §6 states the
  requirement and the conformance suite tests it, but the storage is the host's.
- **Transport.** A credential is an ASCII string.

---

## 2. The binding

A **binding** is the transaction being authorised:

| Field | Type | Notes |
| --- | --- | --- |
| `payer` | UTF-8 string | Opaque; compared byte for byte |
| `payee` | UTF-8 string | Opaque; compared byte for byte |
| `amountMinor` | signed 64-bit integer | Minor units. Never a decimal |
| `feeMinor` | signed 64-bit integer | Minor units |
| `currency` | UTF-8 string | Compared exactly; see §2.3 |
| `reference` | UTF-8 string | Identifies the transaction |
| `context` | byte string | Optional; may be empty |

### 2.1 Digest construction

The digest is `SHA-256` over the concatenation, in exactly this order:

```
field(version) || field(payer) || field(payee) ||
integer(amountMinor) || integer(feeMinor) ||
field(currency) || field(reference) || field(context)
```

where

- `field(x)` = `uint64_be(len(x)) || x`, the length in **bytes** (not
  characters) as 8 bytes big-endian, followed by the bytes;
- `integer(v)` = the two's-complement value of `v` as 8 bytes big-endian;
- `version` is the ASCII bytes of the version string, here
  `bounded-authority/1`.

The digest is transmitted as lowercase hexadecimal.

**Length prefixing is mandatory.** Without it, a payment from `alice` to `bob`
and one from `ali` to `cebob` produce the same digest, and a credential for one
authorises the other. The vectors include this pair (`boundary-a`,
`boundary-b`) so an implementation cannot pass without handling it.

**The version is inside the digest.** A digest computed under one version can
never collide with one computed under another, so a verifier cannot be induced
to accept a credential bound under different rules.

### 2.2 Unicode

Strings are hashed as their UTF-8 bytes with no normalisation. Implementations
MUST NOT apply NFC, NFD, case folding or trimming. Any normalisation must
happen before binding, in the caller, so that issuer and verifier cannot
disagree about what a normalised value is.

The `unicode` vector exists to catch implementations that normalise silently.

### 2.3 Currency

Compared exactly. `GHS` and `ghs` are different transactions. This is
deliberate: a verifier that normalises has to agree forever with an issuer that
normalises, and the two drifting apart is a silent authorisation bug. Callers
SHOULD normalise to ISO 4217 uppercase before binding.

---

## 3. Wire format

```
base64url(payload) "." base64url(signature)
```

Both are base64url **without padding** (RFC 4648 §5).

The signature is Ed25519 over the **ASCII bytes of the encoded payload as
transmitted** — that is, over the base64url text, not over the decoded JSON.
Verifiers MUST NOT re-serialise the payload before checking the signature.
Signing the transmitted bytes removes canonicalisation from the security
argument entirely: there is no JSON ordering, spacing or number-formatting
question, because the bytes that were signed are the bytes that arrived.

### 3.1 Payload

```json
{
  "v":       "bounded-authority/1",
  "jti":     "unique credential identifier",
  "iss":     "issuer name",
  "sub":     "subject the issuer authenticated",
  "method":  "passkey",
  "binding":  "<hex digest from §2.1>",
  "iat":     1700000000,
  "exp":     1700000120
}
```

All fields are REQUIRED. `iat` and `exp` are seconds since the Unix epoch.

Verifiers MUST reject a payload containing any field not listed here. An
unrecognised field means the credential was produced by something that believes
the format has properties this verifier does not implement, and proceeding
means guessing which.

### 3.2 Methods

| Value | Meaning |
| --- | --- |
| `passkey` | Verified WebAuthn assertion from a device-bound credential |
| `hardware_token` | Assertion from a dedicated signing device |
| `delegated_mandate` | Minted under a mandate a human authorised earlier, not a live confirmation |
| `test_authenticator` | No authenticator challenge at all |

`method` is REQUIRED and is carried into evidence. A system where the strength
of an authorisation is knowable only from what configuration was live at the
time cannot answer that question after an incident, which is when it is asked.

`delegated_mandate` is a genuinely weaker assertion than the first two and is
named separately so it cannot be mistaken for one of them in a record.

`method` MUST be one of the four values above — a closed set. Mint and verify
both reject any other value, including a near-miss of a defined one (a trailing
space, different case): an unknown method is not a "valid non-test method", it
is simply not a method, and the field is evidence a reviewer relies on rather
than an arbitrary string.

Verifiers MUST reject `test_authenticator` unless explicitly configured to
accept it. The default MUST be rejection: a deployment that configures nothing
should refuse test credentials, not accept them.

### 3.3 Binding the authenticator challenge

Where the method is `passkey` or `hardware_token`, the issuer SHOULD use the
binding digest (§2.1) **as the authenticator challenge**.

This is the strongest available form of the property and the reason to prefer
this design over a scoped token. When the challenge is the digest, the device
signs the transaction, so a compromised issuer cannot obtain a device signature
for a payment the human did not see. When the challenge is an opaque nonce that
the issuer later associates with a transaction, the issuer is trusted to make
that association correctly, and a compromised one is not.

---

## 4. Verification

A verifier MUST perform these steps, **in this order**:

1. Split on the first `.`. Reject if either part is empty.
2. Decode the payload **without trusting it**, to read `iss`.
3. Look `iss` up in the configured trusted issuers. Reject if absent.
4. Verify the Ed25519 signature over the encoded payload bytes using that
   issuer's key. **Reject before reading any other field.**
5. Re-decode the payload strictly from the bytes that just verified, rejecting
   unknown fields.
6. Reject if `v` is not a version this verifier implements.
7. Reject if `jti` is empty.
8. Reject if `method` is not one of the closed set (§3.2), or is
   `test_authenticator` and the verifier is not configured to accept it.
9. Reject if `exp <= iat` (a credential that expires at or before it was issued),
   or if `exp - iat` exceeds the maximum lifetime (§5). Both are enforced at
   verify as well as at mint, because either end can be the one that is wrong.
10. Reject if `iat > now + skew` (not yet valid) or `exp < now - skew` (expired).
11. Reject if `binding` does not equal the digest of the transaction the
    verifier is about to perform.

Step 4 before step 5 is the whole of the trust argument: nothing inside the
payload influences a decision until the signature over it has verified. Step 2
reads the payload only to select a key, and a wrong guess there fails at step 4.

Step 11 last means a credential presented for the wrong transaction is refused
having consumed nothing (§6.3).

### 4.1 Errors

Verifiers SHOULD distinguish these outcomes rather than collapsing them:

| Outcome | Operational meaning |
| --- | --- |
| binding mismatch | Someone presented authority for a different payment. **Alert.** |
| already consumed | Replay. **Alert.** |
| expired | The customer took too long. Retry. |
| bad signature / untrusted issuer | Forgery or misconfiguration. **Alert.** |
| test method refused | Misconfiguration. |

A single "invalid credential" error makes the first invisible inside the noise
of the third.

---

## 5. Lifetime

Maximum lifetime is **5 minutes**. Maximum clock skew tolerance is **30
seconds**.

The ceiling MUST be enforced when minting **and** when verifying. Enforcing it
only at mint trusts the issuer to be neither compromised nor misconfigured,
which is the assumption this design exists to remove.

A credential authorises one transaction a human has just confirmed. Anything
that lives long enough to be stored, logged and later found is being used as a
session, and a session is what this is not.

Credentials SHOULD NOT be retained after use. A stored credential is a stored
authorisation. Retain the consumption record (§6.1) instead: it carries the
binding digest, which is what an investigation needs.

---

## 6. Single use

Verification does not make a credential single-use. That requires durable state.

### 6.1 The requirement

A host MUST record consumption durably, keyed by `jti`, including at minimum
the `jti`, issuer, subject, method, binding digest and time.

### 6.2 Atomicity

**Recording consumption and performing the authorised effect MUST commit
together, or not at all.**

This is the requirement implementations get wrong, and it does not fail in a
quiet test environment. The common shapes and what they cost:

| Implementation | Failure |
| --- | --- |
| Check, act, then mark | Concurrent presentations all pass the check. **Double spend.** |
| Mark first, then act | A failed effect leaves the credential spent. **The customer must re-authorise a payment that never happened.** |
| Mark in a separate transaction | Both of the above, depending on which commits |

Correspondingly:

- If the effect fails, consumption MUST NOT be durable, and the credential MUST
  remain spendable.
- Exactly one of N concurrent presentations of the same `jti` MUST succeed. The
  others MUST be refused as replays, not lost to lock timeouts — a caller that
  retries after a timeout will succeed.
- The effect MUST run exactly once. A store that retries the effect internally
  can post the same payment twice.
- A replay MUST be refused **before** the effect runs. A store that performs the
  effect and then reports the replay has already moved the money.

### 6.3 Ordering

Binding verification MUST precede consumption. Otherwise anyone who observes a
credential can burn it by presenting it against a transaction of their own
choosing, and the customer's genuine payment fails.

### 6.4 Conformance

[`conformance`](conformance/) checks §6 against a host's implementation. The
checks are enumerable as `conformance.Checks`:

| Check | §6 requirement |
| --- | --- |
| `SpendsOnce` | Consumption and effect are both durable on success |
| `RefusesReplay` | Second presentation refused, effect does not run |
| `DistinctCredentialsBothSpend` | Unrelated credentials are not serialised into failure |
| `FailedEffectRollsBackConsumption` | §6.2, first bullet |
| `FailedEffectRollsBackItsOwnWrite` | The effect ran in the host's transaction |
| `CredentialIsSpendableAfterAFailedEffect` | §6.2, first bullet, from the customer's side |
| `ConcurrentPresentationSpendsExactlyOnce` | §6.2, second bullet |
| `EffectRunsExactlyOnce` | §6.2, third bullet |

The suite is itself tested against two deliberately broken stores, one for each
row of the table in §6.2, so each check has been demonstrated to fail something.

---

## 7. Receipts

A receipt is the evidence half. It records what the host actually did and
carries the binding digest of the credential that permitted it.

Two independent checks apply, and they answer different questions:

- **Intact** — the receipt matches the content hash it carries, so nothing has
  been edited since issue.
- **Matches authority** — two checks. First the receipt's OWN displayed fields
  (payer, payee, amount, fee, currency, reference, context) reproduce the binding
  digest it carries; then that digest equals the digest of the transaction that
  was authorised. The first check is essential: comparing only the stored binding
  string to the authority digest would affirm a receipt that displays one payment
  while citing another transaction's authority.

A receipt can be intact and still describe the wrong payment, if the code that
issued it was wrong. Intactness proves nobody edited it; matching proves it was
right when written. A system that checks only the first has mistaken integrity
for correctness.

A receipt carries the same `context` bytes as the binding it cites, so a binding
that binds a mandate id or policy version can still be reconstructed from the
receipt and matched.

### 7.1 Content hash

`SHA-256` over, in order:

```
field(version) || field(id) || field(reference) || field(effectId) ||
field(payer) || field(payee) || field(currency) || field(description) ||
field(grantId) || field(method) || field(binding) || field(issuedAt) ||
integer(amountMinor) || integer(feeMinor) || field(context)
```

`issuedAt` is hashed as its RFC 3339 representation in UTC.

`issuedAt` MUST be truncated to **microseconds** before hashing. Most databases
store timestamps at microsecond resolution, so a hash over a nanosecond value
verifies in memory and fails after a round trip through storage.

### 7.2 Issuance

A receipt SHOULD be written in the same transaction as the effect. A receipt
written afterwards, by another process, from values passed to it, is an account
of a payment rather than proof of one.

Receipts SHOULD be immutable in storage — enforced by the database, not by
application code that can be bypassed by the next caller.

---

## 8. Test vectors

[`testdata/vectors.json`](testdata/vectors.json) contains binding digests for
eight cases, a signed credential, and a receipt content hash, under a published
test signing key.

An implementation conforms to §2, §3 and §7.1 when it reproduces every one.

The `boundary-a`/`boundary-b` pair fails without length prefixing. The `unicode`
case fails if strings are normalised. The `max-amount` and `negative-amount` cases fail on implementations that treat
amounts as floating point, unsigned, or that mishandle two's-complement.

The signing key is a published test key. It MUST NOT be used in a deployment.

---

## 9. Security considerations

**What this defends against.** A compromised or malicious component that can
compose payment requests — an agent, a front end, a partner, an internal
service — cannot obtain authority for a payment the human did not sign. It
cannot alter the amount, redirect the recipient, or reuse the authority for a
second payment.

**What it does not defend against.** A compromised **issuer** can mint authority
for anything, because the issuer is what attests that a human agreed. §3.3
reduces this: if the authenticator challenge is the binding digest, a
compromised issuer still cannot produce a device signature over a transaction
the human never saw. Deployments SHOULD do this.

A compromised **host** can perform effects without any credential. Verification
therefore belongs at the point the money moves — inside the ledger — not at an
API boundary that internal callers can bypass.

**Key rotation** is out of scope for version 1. Verifiers hold a map of issuer
to key; a deployment rotating keys should trust both during the overlap, which
must exceed the maximum lifetime.

**Confidentiality.** A credential in transit is usable by whoever holds it,
until it is spent or expires — bounded to one transaction, but usable. Transport
MUST be confidential.

**Denial of service.** An attacker who obtains a credential and presents it
against the correct transaction spends it, causing the genuine payment to be
refused as a replay. This is a nuisance rather than a loss: no money moves
anywhere the human did not authorise. Presenting it against a *different*
transaction does not spend it (§6.3).
