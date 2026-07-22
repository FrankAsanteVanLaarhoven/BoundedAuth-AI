# boundedauth

A credential that authorises **one specific movement of money, once** — and a
receipt bound to the same digest, so the proof of what was authorised and the
proof of what happened are the same chain of evidence.

```go
_, err := boundedauth.Authorise(ctx, verifier, store, credential, boundedauth.Binding{
    Payer: "wallet:alice", Payee: "wallet:bob",
    AmountMinor: 50_000, FeeMinor: 250, Currency: "GHS",
    Reference: transferID,
}, func(ctx context.Context, granted boundedauth.Consumption) error {
    // Runs inside the host's transaction. The credential is spent and this
    // effect commits together, or neither happens.
    return ledger.Post(ctx, transferID, granted.ID)
})
```

## Install

```bash
go get github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI
```

```go
import boundedauth "github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
```

The PostgreSQL reference store is a separate module so embedding the verifier
does not pull in a database driver:

```bash
go get github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI/postgres
```

## The problem

A token says who the caller is. It does not say what they agreed to. Anything
holding a valid token can move any amount to any recipient within its scope, as
often as it likes.

That was tolerable when the caller was a person clicking a button. It is not
tolerable when the caller is an automated agent composing payment requests from
text it was given, because the question stops being *is this caller
authenticated* and becomes *did a human agree to **this** payment*.

## What this gives you

The signature covers the transaction — payer, payee, amount, fee, currency,
reference. So:

- A credential obtained for one payment **cannot be presented for another**, by
  anyone, including the service that requested it.
- The authority is **spent exactly once, atomically with the money it moves**.
- Where the authenticator challenge is the binding digest, the **device** signs
  the transaction, so even a compromised issuer cannot obtain a signature for a
  payment the human never saw.

The consequence worth stating plainly: an agent can be wrong,
prompt-injected or hostile, and the worst it achieves is the payment that was
actually signed.

## Why the conformance suite is the important part

The cryptography here is a few hundred lines and either works or fails
obviously. The requirement that gets shipped broken is atomicity — that spending
the credential and doing the work commit together.

A broken implementation passes normal testing and passes review, because the
code reads correctly: look up, check, mark, act. It fails under concurrency and
under partial failure, which is to say it fails in production, on the money
path.

So `conformance` tests **your** store, not this library:

```go
func TestConformance(t *testing.T) {
    conformance.Run(t, conformance.Harness{
        NewStore:  func(t conformance.TB) boundedauth.Store { return myPostgresStore(t) },
        Write:     func(ctx context.Context, key string) error { /* inside the tx */ },
        Committed: func(t conformance.TB, key string) bool { /* observed outside */ },
        Consumed:  func(t conformance.TB, id string) bool { /* observed outside */ },
    })
}
```

It runs the failure modes that do not occur in a quiet test environment:
simultaneous presentation of one credential, and an effect that fails after the
credential has notionally been spent. If your `Write` cannot run inside the
transaction `Consume` opened, the suite fails — correctly, because your store
cannot offer the guarantee whatever its code says.

**The suite is itself tested against two deliberately broken stores**, one for
each classic anti-pattern, so every check has been demonstrated to fail
something. A conformance suite that has never been shown to fail anything is a
claim, not a check.

## What is checkable here

| | How to check it |
| --- | --- |
| The spec is complete enough to implement from | `python3 testdata/verify_vectors.py` — a second implementation, written from `SPEC.md` in another language, reproducing all 9 vectors |
| Binding covers every field that decides where money goes | `go test -run TestEveryBindingFieldChangesTheDigest` |
| A credential cannot be repointed to another payment | `go test -run TestRepointingIsRefused` |
| Repointing does not burn the credential | `go test -run TestARepointedCredentialIsNotSpent` |
| The lifetime ceiling holds even against its own issuer | `go test -run TestLifetimeCeilingIsEnforcedAtVerifyNotOnlyAtMint` |
| Test credentials are refused unless explicitly permitted | `go test -run TestTestMethodIsRefusedByDefault` |
| The in-memory reference store satisfies the atomicity contract | `go test ./memory/... -race` |
| A **PostgreSQL** store satisfies it on a real database | `cd postgres && BOUNDEDAUTH_TEST_DATABASE_URL=... go test ./... -race` |
| The suite catches an effect written on the wrong connection | `go test ./postgres/... -run WrongConnection` |
| The conformance suite fails stores that do not | `go test ./conformance/... -race` |
| A receipt can be intact and still describe the wrong payment | `go test -run TestReceiptIsCheckedAgainstTheAuthorityNotOnlyItself` |

Everything: `go test ./... -race`.

## Not claimed

- **No third-party audit or penetration test.** The tests here are written by
  the same person as the code.
- **No key rotation** in version 1. Verifiers hold a map of issuer to key; a
  rotating deployment trusts both during an overlap longer than the maximum
  lifetime.
- **This does not authenticate anyone.** It verifies a credential minted by an
  issuer you trust. Binding a human to a key is the issuer's job.
- **A compromised issuer can mint authority for anything.** §3.3 of the spec
  reduces this and does not eliminate it.
- **`memory` is not durable** and is a reference implementation, not a store.
- **No production deployment.** It was extracted from a payment platform that
  has never handled live funds.

## Layout

| | |
| --- | --- |
| `authority.go` | Binding digest, mint, verify |
| `store.go` | The `Store` contract and `Authorise` |
| `receipt.go` | Receipts bound to the authority that permitted them |
| `conformance/` | Checks a host's store; tested against broken stores |
| `memory/` | Reference store, passes the suite under `-race` |
| `postgres/` | PostgreSQL reference store — separate module, so the core keeps zero dependencies |
| `SPEC.md` | Normative specification |
| `testdata/` | Cross-language vectors and a second implementation |

The core has zero dependencies outside the Go standard library. `postgres/` is a
separate module so that embedding a verifier does not pull in a database driver.

## Who implements it

| Implementation | Status |
| --- | --- |
| `memory` | Reference. Passes the suite under `-race` |
| `postgres` | Reference. Passes on a real PostgreSQL under `-race` |
| EPHERA ledger | Passes the same suite, exercising the statement that posts money |

The last row is the one worth reading twice. The contract was extracted from
that ledger, which makes it the implementation most likely to be assumed
correct and least likely to be tested against the thing it inspired. It is now
judged by the same suite as an outside implementation would be.

## Licence

Not yet assigned.
