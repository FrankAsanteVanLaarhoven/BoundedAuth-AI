# Adopting bounded authority

How to put this into a system that already moves money, what it costs, how to
migrate without a flag day, and how to run it afterwards.

This document assumes you have read [`SPEC.md`](SPEC.md). It is deliberately
opinionated: where there is a choice that is nearly always wrong, it says so
rather than presenting both options neutrally.

---

## 0. Decide whether you need it

Adopt this if **any** of these is true:

- A component that composes payment requests is not fully trusted — an agent,
  a partner integration, a third-party front end, anything driven by text.
- You need to prove *after the fact* that a specific human authorised a
  specific payment, to a regulator, a court, or a counterparty in a dispute.
- Your current authorisation is a bearer token, and the blast radius of that
  token leaking is "anything within its scope".

Do **not** adopt it if all your payment initiation is server-side, batch, and
already covered by a mandate you can evidence some other way. It would be
ceremony without benefit, and the operational cost below is real.

### What it costs, measured

From [the workload study](notebooks/ieee-cis-workload-study.ipynb) — 50,000
real transactions from the IEEE-CIS dataset, PostgreSQL on the same host:

| | |
| --- | --- |
| Verification alone | 0.031 ms p50, ~31,300/s per core |
| Full path, verify + spend + post atomically | 3.11 ms p50 at 64 workers, ~21,000/s (median of 3 runs) |
| Saturation | 64–128 workers against a 60-connection pool |
| Refusing a replay | 0.51 ms — roughly 3× cheaper than accepting |
| Penalty for payer concentration | +1 ms p50, −20% throughput for the busiest payers |
| Genuine row serialisation, for comparison | +32.6 ms p50, −94% throughput |

**The cryptography is not the cost.** Verification is 1% of the path; the
database commit is the rest. If you are already committing a transaction per
payment — and if you are moving money, you are — the marginal cost of this is
a single additional row insert in that same transaction.

---

## 1. The five decisions

Make these explicitly before writing code. Each has a default that is right for
most adopters, and a reason.

| Decision | Default | Why |
| --- | --- | --- |
| **Where does verification happen?** | At the point money moves — inside the ledger | An API-gateway check is bypassed by any internal caller. The whole model assumes internal services can be compromised |
| **Who issues?** | The service that authenticates the human, and nothing else | Every additional issuer is another key that can mint authority for anything |
| **What is the authenticator challenge?** | The binding digest itself | Otherwise a compromised issuer can associate a device signature with a payment the human never saw (SPEC §3.3) |
| **What goes in `reference`?** | Your transfer/payment identifier | It is the anchor for single use and for reconciling a spent credential to a payment |
| **What goes in `context`?** | Mandate ID, policy version, agent identity — anything an investigator will want bound | It is covered by the signature at no extra cost. Adding it later is a version change |

---

## 2. Integration, step by step

### Step 1 — Schema

Apply [`postgres/schema.sql`](postgres/schema.sql), or its equivalent for your
database. Two properties are non-negotiable:

- **A primary key on the credential identifier.** This is the control, not an
  index. Single use must be enforced by the database, because that is the only
  place concurrent requests are actually serialised.
- **Append-only.** `UPDATE` and `DELETE` refused by trigger. Deleting a
  consumption record makes a spent credential spendable again.

### Step 2 — Implement `Store`, or use the reference

If PostgreSQL: use [`postgres`](postgres/). It is a separate Go module so the
verifier does not drag a database driver into services that only verify.

If not: implement `Store.Consume`. The entire contract is that recording
consumption and performing the effect **commit together**. In practice:

```go
func (s *MyStore) Consume(ctx context.Context, rec boundedauth.Consumption,
                          effect func(context.Context) error) error {
    tx := begin()
    defer rollback(tx)                    // covers panics and every error path

    if err := insertConsumption(tx, rec); err != nil {
        if isDuplicateKey(err) {
            return boundedauth.ErrAlreadyConsumed   // BEFORE the effect runs
        }
        return err
    }
    if err := effect(withTx(ctx, tx)); err != nil {
        return err                        // rolls back; credential stays spendable
    }
    return commit(tx)
}
```

Note there is **no `SELECT`**. A read to check whether the credential was spent,
followed by an insert, is two operations with a gap between them, and the gap is
the double spend. Let the primary key raise.

### Step 3 — Run the conformance suite. This is the gate.

```go
func TestConformance(t *testing.T) {
    conformance.Run(t, conformance.Harness{ /* … */ })
}
```

**Do not proceed until it passes under `-race`, against your real database.**
An in-memory pass proves nothing: what the contract requires is a property of
your transaction.

If `Write` cannot run on the transaction that `Consume` opened, stop. You have
learned that your storage layer cannot offer this guarantee — that is a real
finding, and it is much cheaper now than after launch.

### Step 4 — Issue

Hold the private key in an HSM or KMS. It mints authority for money movement;
treat it as you would a signing key for settlement instructions.

Where the method is `passkey`, use the binding digest as the WebAuthn challenge:

```go
b := boundedauth.Binding{Payer: …, Payee: …, AmountMinor: …, Reference: transferID}
challenge := b.Digest()          // the device signs THIS
// … run the WebAuthn assertion with challenge …
credential, err := issuer.Mint(boundedauth.Payload{
    ID: uuid(), Subject: userID, Method: boundedauth.MethodPasskey,
    Binding: b.Digest(),
    IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(),
})
```

The customer's device has now signed the transaction, not a nonce. This is the
single most valuable line in the integration.

### Step 5 — Verify where the money moves

```go
verifier := boundedauth.Verifier{
    TrustedIssuers: map[string]ed25519.PublicKey{"identity.prod": pub},
    // AllowTestMethod stays false in production. The default is refusal.
}
```

Configure it to **fail closed**: no key configured must mean no payment posts,
not "skip the check". An unverifiable authorisation is not an authorisation.

### Step 6 — Migrating from bearer tokens, without a flag day

The dangerous path is a big-bang cutover; the *more* dangerous path is running
both permanently, because the old path stays exploitable and gets forgotten.

1. **Shadow.** Issue and verify credentials alongside the existing check.
   Post on the old check. Log every disagreement.
2. **Read the disagreements.** Every one is either a bug in your binding
   construction (usually amount rounding or a reference mismatch) or a request
   that should never have been authorised. Both are worth knowing before cutover.
3. **Enforce for one flow**, chosen for volume rather than for risk — you want
   the migration bugs to surface, and low-volume flows hide them.
4. **Enforce everywhere.**
5. **Delete the old path in the same release.** Not the next one. A disabled
   bypass that still compiles is a bypass.

Keep a kill switch that **fails closed** — if the control plane is unreachable,
payments stop rather than falling back to the old check. A kill switch that
degrades to "allow" is an attacker's first target.

### Step 7 — Operations

**Alert on these. They mean someone is trying something:**

| Signal | Meaning |
| --- | --- |
| `ErrBindingMismatch` | Authority presented for a different payment. **Page someone** |
| `ErrAlreadyConsumed` above baseline | Replay attempts, or a broken client retry loop |
| `ErrBadSignature` / `ErrUntrustedIssuer` | Forgery, or a botched key rotation |
| `ErrTestMethodRefused` in production | Misconfiguration — or a test issuer reachable from production |

Do not collapse these into "invalid credential". The first is an attack and the
third is an outage, and one error metric makes the attack invisible inside the
noise of ordinary expiries.

**Expect a steady low rate of `ErrExpired`.** Customers get distracted. That is
the control working.

**Key rotation** is not in version 1. Until it is: hold both keys in
`TrustedIssuers` during an overlap comfortably longer than `MaxLifetime`, then
remove the old one.

**Retention.** Keep consumption records; they are your evidence. Do **not**
retain the credentials themselves — a stored credential is a stored
authorisation. The consumption record carries the binding digest, which is what
an investigation actually needs.

---

## 3. How EPHERA uses it

Concretely, so the guide is not abstract:

- **Issuer:** `identity-access` — the only holder of a private key. It runs the
  WebAuthn ceremony with the binding digest as the challenge.
- **Verifier:** the **ledger**, not the API layer. The payment orchestrator
  parses the credential to fail fast on an obviously wrong one, but its opinion
  authorises nothing. If the ledger has no public key configured it refuses
  every transfer.
- **Consumption:** the `authorisation_grants` table, primary key on `jti`,
  inserted in the same transaction as the postings, the evidence row and the
  receipt.
- **Receipt:** issued in that same transaction, carrying the binding digest and
  the same fields it was posted with. A receipt that displays a payment other
  than the one authorised does not pass `MatchesAuthority` — its own fields must
  reproduce the binding it cites — so a mismatch between what a receipt shows and
  what was authorised is detectable, not silent.
- **Conformance:** the ledger is run against the same suite an outside adopter
  would use. It exercises the exact statement `CaptureTransfer` uses to post
  money, so a regression in single use fails the suite.

**One thing stated plainly:** `CaptureTransfer` does not route through
`Store.Consume`. It opens its own transaction, because it does far more than one
effect — holds, postings, fee splits, evidence, receipt. What ties them together
is the shared consuming statement, not shared control flow. A reviewer will
notice this; better to read it here first.

---

## 4. Checklist

Before you call it adopted:

- [ ] Conformance suite passes under `-race`, against the real database
- [ ] Verification happens where money moves, not at an API boundary
- [ ] No key configured ⇒ payments refused (verified by test, not by reading code)
- [ ] `AllowTestMethod` is false in production, and asserted in a test
- [ ] The authenticator challenge is the binding digest
- [ ] Consumption table is append-only, enforced by the database
- [ ] Binding includes every field that determines where money goes
- [ ] Amount rounding happens once, at the edge, before binding
- [ ] Distinct alerts for mismatch / replay / bad signature / expiry
- [ ] Private key in an HSM or KMS
- [ ] Credentials are not retained after use; consumption records are
- [ ] The old authorisation path is deleted, not disabled
- [ ] Kill switch fails closed

---

## 5. Ways to get this wrong

Each of these has been shipped by somebody, and most of them read correctly.

| Mistake | Consequence |
| --- | --- |
| `SELECT` then `INSERT` to check single use | Double spend under concurrency. The conformance suite catches this |
| The effect on a different connection from `Consume` | The payment survives a rolled-back authorisation. The suite catches this |
| Marking consumed before the effect | A failed payment burns the customer's authorisation, and they must re-approve a payment that never happened |
| Verifying at the API gateway | Any internal caller bypasses it entirely |
| Normalising strings inside the digest | Issuer and verifier drift apart; a silent authorisation bug |
| Amounts as floats | The digest stops reproducing. Use integer minor units |
| Consuming *before* checking the binding | An observer can burn a customer's credential by presenting it against a transaction of their own choosing |
| Lifetime enforced only at mint | A compromised issuer mints a credential that lives for a day |
| Retaining credentials for audit | You are storing live authority. Retain consumption records |
| One error type for every failure | Attacks become invisible inside ordinary expiries |
| `AllowTestMethod` true in production | A test authenticator authorises real money |

---

## 6. What adoption does not give you

- It does not stop a customer being **deceived into authorising** a payment. The
  authorisation is genuine. That is a detection problem, and needs a separate
  control — see the workload study, §6.
- It does not authenticate anyone. It verifies a credential from an issuer you
  trust.
- It does not protect against a **compromised issuer**, beyond what using the
  binding digest as the challenge buys you.
- It does not protect against a **compromised host** performing effects with no
  credential at all. That is why verification belongs at the point money moves.
