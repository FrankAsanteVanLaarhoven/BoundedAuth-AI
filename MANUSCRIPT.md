# BoundedAuth — Engineering Research Manuscript

**A transaction-bound, single-use authorisation credential for money movement:
hypothesis, method, failures, refinement, and evidence-based validation.**

| | |
| --- | --- |
| **Author** | Frank Asante Van Laarhoven (ORCID 0009-0006-8931-0364) |
| **Artefact** | `github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI` |
| **Version** | 1.0.0 (manuscript), library `bounded-authority/1` |
| **Date** | 2026-07-23 |
| **Status** | Self-validated (unit + conformance + cross-language + workload + internal red-team). **Not third-party audited or certified** — see §26. |
| **Reproducibility** | Every quantitative claim maps to a command in §25. |

> This manuscript is deliberately separate from the [README](README.md) (which
> is the adopter-facing summary), the [SPEC](SPEC.md) (normative rules), and the
> [ADOPTION guide](ADOPTION.md) (integration). It is the *research record*: what
> was hypothesised, what failed, what was decided, and what the evidence
> actually supports. It records the mistakes on purpose — a security artefact
> whose development history contains no failures is either very young or not
> telling you everything.

---

## Abstract

Authorisation in payment systems is almost universally a **bearer token**: a
string that attests *who is calling*, not *what they agreed to*. This was
tolerable when the caller was a person pressing a button; it is not tolerable
when the caller is an automated agent composing payment requests from text it was
handed. We define, specify, implement, and empirically evaluate a **bounded
authority**: a credential whose signature covers the exact transaction, that is
spent exactly once atomically with the money it moves, and whose receipt is bound
to the same digest. The central methodological contribution is not the
cryptography (which is small and either works or fails obviously) but a
**portable conformance suite that tests the adopter's own database** for the
single property everyone implements wrong — atomicity of single use — together
with a self-test proving the suite fails broken implementations. We report three
implementations that pass, ten cross-language test vectors reproduced from the
specification alone, a workload study on 590,540 real transactions, and an
internal red-team that found and fixed five defects before publication. We are
explicit about what is *not* validated: no third-party audit, no key rotation, no
production deployment with live funds.

---

# PART I — THE RESEARCH NARRATIVE

## 1. Hypothesis

The work began from a specific dissatisfaction with bearer authorisation, and was
framed as three falsifiable hypotheses:

> **H1 — Separability.** The transaction-bound authorisation built inside a
> payments platform is not specific to that platform. It can be stated as a
> general contract an unrelated system can adopt, without losing any property.

> **H2 — Checkability.** The property that matters — a credential spent exactly
> once, atomically with the money it moves — can be verified *in someone else's
> implementation*, by a portable test suite, rather than asserted in prose.

> **H3 — Affordability.** Making every payment carry such a credential is
> affordable at realistic traffic shapes, and its refusal paths do not degrade
> under volume.

H1 and H2 are engineering claims, falsified by extraction failing or by the suite
being unable to discriminate correct from incorrect stores. H3 is empirical and
requires real traffic.

## 2. Design

**The credential.** A *binding* is the transaction: payer, payee, amount, fee,
currency, reference, and optional opaque context. Its digest is SHA-256 over
**length-prefixed** fields — without prefixing, `alice→bob` and `ali→cebob` hash
identically and a credential for one authorises the other. The version string is
inside the digest, so a digest under one version can never collide with one under
another. The credential is that digest, signed Ed25519 by a named issuer, with a
subject, a method, a unique identifier (`jti`), and a five-minute lifetime ceiling
enforced **at mint and at verify** — both ends, because either end can be the one
that is compromised.

**The sharpest design edge is a deployment recommendation, not a mechanism:** use
the binding digest *as* the WebAuthn challenge. Then the customer's device signs
the transaction rather than an opaque nonce, and even a compromised issuer cannot
obtain a device signature for a payment the human never saw.

**The contract.** Verification alone leaves a credential infinitely replayable.
Single use needs durable state, and — the part that is easy to miss — that state
must commit *in the same transaction as the effect*. That is a property of the
host's storage, not of a library. So the design splits: the library verifies; the
host implements a `Store` whose `Consume` records consumption and runs the effect
atomically. The library supplies a **conformance suite** that tests the host.
Binding verification precedes consumption, so a credential presented for the wrong
transaction is refused *without being spent* — otherwise anyone observing a
credential could destroy it by presenting it against a transaction of their own.

## 3. Initial result — extraction exposed two latent defects (H1)

Carving the code out of its origin platform was expected to be mechanical. It was
not.

- **The issuer was a package constant.** No second party could use the library at
  all, and — worse — there was no way to trust a second issuer without widening
  what the first could authorise. Fixed by making the verifier a value holding a
  per-issuer key map.
- **Single use was welded to one ledger table.** Generalising forced the real
  requirement into the open: not "record the identifier" but "record it in the
  same transaction as the effect."

H1 survived, but only after generalisation acted as a *defect detector*. Neither
problem was visible while the code had exactly one caller.

## 4. Failure — the conformance suite passed a broken store, one run in five

This is the most instructive failure in the project.

A conformance suite that has never been shown to fail anything is a claim, not a
check. So the suite was run against a deliberately broken store: check, release
the lock, act, then mark — the shape that gets written, reviewed, and shipped
because it *reads* correctly.

**Initial result: the concurrency check caught the double-spend only about four
times in five.** The Go scheduler serialised the sixteen goroutines often enough
that the broken store simply never exhibited the defect within a single run.

A check that catches a defect 80% of the time is *worse than no check*, because it
issues a passing conformance result that a host will rely on. A broken store could
pass by luck. A second, subtler failure: a single contrived broken store could not
exhibit every defect the suite claimed to detect — check-then-act does not burn
the credential on a failed effect, so the rollback checks had nothing to catch.

## 5. Refinement

**The concurrency check now forces overlap instead of hoping for it.** The effect
holds a barrier: each attempt waits until all sixteen have arrived, or until a
200 ms timeout. A correct store admits exactly one goroutine, which waits out the
timeout alone and proceeds — costing one timeout per run. A broken store admits
all sixteen, the barrier opens immediately, and they overlap by construction. The
check also asserts on *how many* attempts entered the effect, converting a
probabilistic observation into a structural one. Verified over eight consecutive
race-enabled runs, deterministic in both directions.

**The self-test now uses multiple broken stores**, each embodying one real
anti-pattern, each asserted against the specific checks it must fail — plus an
assertion that *not every* check fails (a suite that rejects all stores is as
uninformative as one that accepts all of them).

## 6. Further experiment — a real database and a real workload

**A PostgreSQL reference store (H2 on real infrastructure).** An in-memory pass
does not establish a transactional property. Its central choice: **single use
comes from the primary key, not from a read.** There is no `SELECT`. A check
followed by an insert is two operations with a gap, and the gap is the double
spend; the insert either succeeds or raises a unique violation, and PostgreSQL
resolves concurrency internally. It passes the suite on a real database under the
race detector, and a second harness runs the same store with the effect writing
on the *pool instead of the transaction* — the mistake that reads identically and
passes ordinary tests. The suite catches it.

**A real workload (H3).** Synthetic benchmarks spread load uniformly; real payment
traffic concentrates. The IEEE-CIS Fraud Detection dataset (590,540 real card
transactions) was used for its *shape*, verified against published
characteristics before use (`sha256 3a5c83ab…`, 3.50% fraud rate, 13,553 distinct
payers, Gini 0.888, top-1% of payers = 52.8% of traffic). 50,000 transactions were
replayed through mint → verify → consume-and-post-atomically against PostgreSQL.

| Measurement | Result |
| --- | --- |
| Verification alone (single core) | **31,337/s**, p50 **0.031 ms** |
| Full path, 64 workers | **20,985/s**, p50 **3.11 ms** (median of 3 runs) |
| Saturation | plateaus at 64–128 workers against a 60-connection pool |
| Replay attempts | **5,000 / 5,000 refused**, p50 0.51 ms (≈3× cheaper than acceptance) |
| Repointing attempts | **1,000 / 1,000 refused**, **0** credentials burned |
| Effects failed deliberately | 667; **667** credentials still spendable, **0** lost |
| Payer concentration penalty | +1 ms p50, −20% throughput (busiest 10 payers) |
| Control — genuine row serialisation | +32.6 ms p50, −94% throughput (15.9×) |

## 7. Insight

- **The cryptography is not the cost.** Verification is 0.031 ms against a 3.11 ms
  full path — under 1%. The intuition that transaction-bound authorisation is
  expensive is an intuition about signatures, and it is wrong; the cost is the
  database commit a payment system already pays.
- **Refusal is ~3× cheaper than acceptance** — an unintended *load-shedding*
  property: an attacker replaying credentials does less work per request than a
  legitimate customer, so a replay flood degrades the system slower than paying
  traffic does.
- **The most valuable result is a zero.** 1,000 repointing attempts burned **0**
  credentials. Refusing a repointed credential is the obvious requirement; the
  subtle one is that refusal must *not spend it*, or an observer could destroy a
  customer's authority at will. The ordering decision produces that zero, and it
  would have been easy to get backwards.
- **Generalisation is a defect detector** (§3), and **a test that usually catches
  a defect is a liability** (§4). These are the two findings most likely to
  transfer to other work.
- **A benchmark reporting "no effect" must prove it can detect the effect.** Two
  of this study's early null results were wrong before that discipline was applied
  (see §22); the sensitivity control (the 34.7 ms shared-row cohort) is what made
  the contention null result trustworthy.

## 8. Conclusion

- **H1 (separability) — supported.** Extracted with zero dependencies outside the
  standard library and adopted by an unrelated implementation; extraction exposed
  two latent defects, itself evidence the abstraction was doing work.
- **H2 (checkability) — supported, and the transferable contribution.** The
  property is checkable in someone else's implementation. Three implementations
  pass; the suite is demonstrated to fail realistic anti-patterns; the suite's own
  probabilistic failure, found and fixed, is part of the evidence it was tested
  rather than trusted.
- **H3 (affordability) — supported within stated limits.** ~3 ms median, ~21,000
  authorised payments/s on one commodity host, flat latency until saturation, a
  small (~20%) penalty for payer concentration against a 15.9× penalty for genuine
  serialisation, every adversarial path refused at volume.

The strongest defensible statement: *making every payment carry a
transaction-bound, single-use authorisation is affordable at realistic traffic
shapes; its refusal paths hold under volume; and — unusually for a security
control — whether an adopter has implemented it correctly is decidable by running
a suite rather than by reading their code.*

## 9. Refined structure and evidence-based validation

The artefact is structured so each claim has a corresponding executable check:

| Layer | Artefact | Evidence |
| --- | --- | --- |
| Format | `authority.go`, `SPEC.md` | 10 cross-language vectors reproduced in Python from the spec |
| Verifier | `Verifier.Verify` | unit tests: forge, repoint, expiry, lifetime-at-verify, method enum |
| Contract | `Store`, `conformance/` | self-test fails three broken stores; three implementations pass |
| Durability | `postgres/` | primary-key single use + immutable consumption, under `-race` |
| Evidence | `receipt.go` | `Intact` vs `MatchesAuthority` (self-binding recomputed) |
| Empirical | `bench/`, `notebooks/` | IEEE-CIS workload, 50k transactions |
| Adversarial | internal red-team | five findings fixed with a regression test each (§22) |

---

# PART II — 5W1H FRAMING

## 10. What

A standalone Go library — a credential *format* + *verifier* + *conformance suite*
+ reference stores — for authorising money movement. It is the authorisation
primitive extracted from a payments platform, published so it can be adopted or
licensed independently.

## 11. Why

Every system placing an untrusted or non-deterministic component near a money path
faces the same unsolved problem: how to let that component *propose* a payment
without letting it *authorise* one. Bearer tokens cannot express "a human agreed
to *this* transaction." A transaction-bound, single-use credential can, and makes
the guarantee checkable rather than assumed.

## 12. When

Now (2026), against a live and unresolved need: agentic-commerce and
mandate-based payment efforts are converging on this exact question, and the
common answer — a scoped bearer token — does not bind to a transaction. The
primitive is deployment-ready as a library; production use with live funds is
future work.

## 13. Where

Any money path with an untrusted or automated proposer: remittance corridors,
mobile money, agentic payments, partner/marketplace integrations, internal
service-to-service payment flows. It is transport- and ledger-agnostic; the
reference stores are in-memory and PostgreSQL.

## 14. Who

- **Author / principal:** Frank Asante Van Laarhoven.
- **Adopters:** payment institutions, EMIs, fintech platforms, and any team
  deploying agents that can move money.
- **Beneficiaries:** end customers (whose funds cannot be moved without a signature
  over the exact transaction) and operators (who gain checkable evidence).

## 15. How

Issuer authenticates a human and mints a credential (challenge = binding digest);
the caller presents it with the transaction; the verifier checks the signature
before trusting any field, then the host's `Store` spends it once atomically with
the ledger effect; a receipt is bound to the same digest. Correctness of the
host's implementation is established by running the conformance suite.

---

# PART III — IMPLEMENTATION GOVERNANCE

> **Advisory notice.** §16–§23 describe governance, funding, and commercial
> structure. Where they touch real financial or legal facts (specific figures,
> counterparties, grant terms), they are the *recommended model* and require the
> principal's confirmation before being treated as binding. They are marked
> **(advisory)** accordingly. No specific monetary amounts are asserted.

## 16. SMART objectives for implementation

| Objective | Specific / Measurable / Achievable / Relevant / Time-bound |
| --- | --- |
| **O1 — Conformance-verified adopters** | ≥1 external implementation passes the conformance suite unmodified. Measured by a green suite run in the adopter's CI. Achievable via the published harness. 0→1 within an adoption engagement. |
| **O2 — Independent reimplementation** | A second-language implementation reproduces all 10 vectors. **Achieved** (Python). Extend to a third language (e.g. TypeScript) within 1 quarter. |
| **O3 — Third-party assurance** | Commission an external cryptographic/security review. Measured by a signed report. The one assurance the author cannot self-produce (§26). Target: before any production deployment. |
| **O4 — Production reference** | One live deployment moving real funds behind the contract, with observability. Time-bound to sponsor/EMI authorisation, not to a calendar date. |
| **O5 — Key rotation** | Ship a managed rotation flow (v2). Measured by a rotation runbook + test. Within 1–2 quarters of first adopter demand. |

## 17. KPIs

**Correctness (leading):** conformance-suite pass rate across implementations
(target 100%); cross-language vector reproduction (target 10/10, **currently
10/10**); red-team findings open vs closed (**currently 0 open**); regression
tests per finding (**currently 1:1**).

**Performance (measured, single host):** verification latency p50 (**0.031 ms**);
full-path p50 (**3.11 ms**); refusal-vs-acceptance cost ratio (**~3×**);
credentials burned by refusal (**target 0; measured 0/1,000**); credentials lost
to a failed effect (**target 0; measured 0/667**).

**Adoption (lagging):** external implementations passing the suite; production
deployments; independent audits completed.

KPIs are honest about direction: leading indicators (correctness) are strong;
lagging indicators (adoption, audit, production) are at zero and named as such.

## 18. Governance & compliance

- **Change control.** The wire format is versioned (`bounded-authority/1`). The
  cross-language vectors are pinned by a stability test; changing any digest is a
  deliberate version change, not a silent edit — CI fails otherwise.
- **Provenance.** Single-author artefact under one Git identity; every commit and
  push passes an attribution guard.
- **Regulatory posture.** The library is an *authorisation primitive*, not a
  regulated activity in itself. In a payment institution it supports SCA/strong
  customer authentication evidence (transaction-bound signatures), auditability
  (single chain from authority to receipt), and model-risk separation (no model on
  the authorisation path). It does **not** by itself discharge AML, sanctions,
  safeguarding, or licensing obligations — those are the adopter's, and are
  explicitly out of scope (§20, §27).

## 19. Financial separation (advisory)

An **open-core** separation is recommended and is the natural shape of the
artefact:

- **Open / non-revenue:** the specification, the verifier, the conformance suite,
  the reference stores, and the vectors. These are the trust-establishing assets
  and derive their value from being inspectable; they should not sit behind a
  paywall.
- **Commercial / revenue-bearing:** a managed issuer (HSM/KMS-backed key custody),
  evidence-retention and dispute-grade proof services, support and certification
  of adopters, and per-verification metering if offered as a service.

This separates the *trust substrate* (must be free to inspect) from the
*operational product* (may be licensed) and keeps the incentive to overstate the
free artefact's guarantees at zero — the conformance suite would expose it.

## 20. Remuneration clarification (advisory)

- The artefact is the work of a single named author; **no undisclosed contributor,
  co-author, tool, or vendor attribution exists** in the repository.
- No external funding, grant, or remuneration is asserted by this manuscript. If
  the work is later funded (grant, sponsor, or commercial licence), remuneration
  and IP terms must be recorded in a governance document that this section links
  to; they are **not** invented here.
- Where public-benefit funding is involved, remuneration for commercial services
  (§19) must be ring-fenced from any public/grant-funded development, with a
  documented cost-allocation basis (§21). This is a recommendation, not a
  statement that such funding exists.

## 21. Project allocation accuracy (advisory)

Effort to date is attributable to distinct, separately-evidenced work packages:
format & verifier; the conformance suite and its self-test; the PostgreSQL
reference store; the cross-language vectors; the workload benchmark; and the
red-team remediation. Each maps to specific files and commits, so cost allocation
(if funding is introduced) can be evidenced per work package rather than estimated.
No allocation percentages are asserted without a funding structure to allocate
against.

## 22. Public benefit delivery

The public-benefit case is concrete and does not depend on commercialisation:

- **A reusable safety primitive, openly specified.** Anyone building near a money
  path can adopt bounded authority; the harder half (correct single-use atomicity)
  is made checkable, lowering the barrier to doing it right.
- **Consumer protection by construction.** A customer's funds cannot be moved
  without a signature over the exact transaction they approved; the worst a
  hostile intermediary achieves is the payment the human actually signed.
- **Corridor relevance.** The origin platform targets the UK–Ghana remittance
  corridor — a market where authorisation integrity directly protects lower-income
  senders from unauthorised or misdirected transfers.
- **Transparency as a public good.** The specification, the conformance suite, and
  this manuscript (including its failures) are public, so the claims are checkable
  by anyone rather than taken on trust.

## 23. Commercial viability

- **Wedge.** The one primitive nobody currently sells with all three properties
  together — signature covers the transaction, spent once with the money, receipt
  proves the outcome — right as agentic payments create demand for exactly this.
- **Model.** Open spec/verifier for adoption and trust; revenue from managed
  issuer, evidence retention, dispute-grade proof, and adopter certification (§19).
  Metering fits a per-verification shape, like an authorisation network.
- **Moat.** Not the code (a few hundred lines) but the **conformance suite + the
  record of it failing broken implementations** — the credibility asset. Adoption
  compounds: once a verifier is embedded in someone else's ledger, switching cost
  is high.
- **The honest risk.** A format is worth nothing until someone else's ledger
  embeds the verifier. If nobody adopts it, this is a well-tested library. That
  argues for open-sourcing the trust substrate and charging for the operational
  product, not the reverse.

---

# PART IV — RISK, LIMITATIONS, AND THE UNGLAMOROUS RECORD

## 24. Risk management

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| **Compromised issuer mints arbitrary authority** | Low | Critical | Device-signs-the-digest (§2) reduces to "cannot sign a payment the human never saw"; issuer key in HSM/KMS; per-issuer trust so blast radius is one issuer. |
| **Host implements single-use non-atomically** | Medium | Critical | The conformance suite exists precisely for this; it is the primary control, and it is proven to fail the common broken shapes. |
| **A false "no defect" from a weak test** | Medium | High | The 1-in-5 failure (§4) taught the lesson; concurrency is now barrier-forced and structural; benchmarks carry sensitivity controls. |
| **No third-party assurance before production** | High (current) | High | Named as an open objective (O3); production gated behind it. |
| **Adoption fails; artefact unused** | Medium | Commercial | Open the trust substrate; charge for operations; keep the primitive dependency-free to lower adoption cost. |
| **Key rotation absent (v1)** | Certain | Medium | Documented workaround (overlap window); v2 objective (O5). |
| **Format drift between implementations** | Low | High | Pinned vectors + CI stability test; version inside the digest. |

## 25. Reproducing every claim

```bash
git clone https://github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI && cd BoundedAuth-AI

# Correctness of the credential, receipts, and the conformance suite (race detector)
go test ./... -race

# The suite is proven to FAIL broken stores (run repeatedly for determinism)
go test ./conformance/... -race -count=3

# The spec is complete enough to reimplement: a second-language implementation
# reproduces all 10 vectors from SPEC.md rules
python3 testdata/verify_vectors.py

# The PostgreSQL reference store satisfies the contract on a real database
docker run -d -e POSTGRES_USER=b -e POSTGRES_PASSWORD=b -e POSTGRES_DB=boundedauth_ref -p 5433:5432 postgres:16-alpine
cd postgres && BOUNDEDAUTH_TEST_DATABASE_URL='postgres://b:b@localhost:5433/boundedauth_ref?sslmode=disable' go test ./... -race

# The workload study (needs the IEEE-CIS dataset; sha256 printed in the notebook)
cd bench && go run . -csv <train_transaction.csv> -db "$BOUNDEDAUTH_TEST_DATABASE_URL" -limit 50000 -repeats 3
```

Each row of the README's "What is checkable" table names the single test behind
one claim. The workload figures reproduce from `bench/results/ieee-cis-50k.json`
and the executed [notebook](notebooks/ieee-cis-workload-study.ipynb).

## 26. Validation and certification status

**What is validated (self-certified):**

- Unit correctness of format, verifier, and receipts (`go test -race`).
- The conformance contract, with a self-test proving the suite fails three
  realistic broken-store anti-patterns.
- Cross-language reproduction of all 10 vectors from the specification.
- The PostgreSQL reference store under the race detector.
- A workload study on 590,540 real transactions.
- An **internal adversarial red-team** (see §22-findings below), all findings fixed
  with regression tests.

**What is NOT validated — stated plainly, because a security artefact that claims
certification it does not hold is exactly the failure it exists to prevent:**

- **No independent third-party cryptographic or security audit.** The tests are
  written by the author of the code. "Certified" in any external, accredited sense
  is **not** claimed.
- **No formal verification** of the protocol.
- **No production deployment** with live funds.
- **No key-rotation** mechanism (v1).

The path to external certification is objective O3; production is gated behind it.

### 22-findings — the internal red-team record (what was bad, and the fixes)

The published module was adversarially reviewed before this manuscript. The
credential half held (forge, repoint, replay all refused; PostgreSQL single-use
and atomicity verified under `-race`). The defects, all fixed with a regression
test each:

1. **(High) A receipt could display one payment while citing another's authority**
   and pass both integrity checks, because `MatchesAuthority` compared only the
   stored binding string. Fixed: it now also requires the receipt's own fields to
   reproduce the binding it carries; a `Context` field was added so
   context-bearing bindings can be reproduced at all.
2. **(Medium) The verifier accepted arbitrary `method` strings**, voiding the
   method's evidentiary value and letting a near-miss of `test_authenticator` slip
   the test gate. Fixed: method is a closed set, refused at mint and verify.
3. **(Medium) One conformance check was never demonstrated** against a broken
   store. Fixed: a third broken store (double-effect) was added and the suite must
   catch it.
4. **(Low) A credential with `exp ≤ iat`** was accepted at verify though refused at
   mint. Fixed: both ends enforce it.
5. **(Low) No negative-amount vector.** Fixed: added, so a cross-language
   implementation mishandling two's-complement cannot reproduce the vectors by
   luck.

## 27. Limitations, uncertainties, and alternatives

**Limitations.** Single-author artefact; no third-party audit; no production use;
no key rotation; the workload study runs on a single host (absolute throughput is
not a capacity claim — the scaling *shape* and *relative* costs are the
transferable results); the origin platform's rails are simulated; screening and
AML are out of scope.

**Uncertainties.** Whether the abstraction survives *many* independent adopters
(only one external + reference + origin so far); whether the ~20% payer-concentration
throughput penalty is real or within run-to-run spread (the 15.9× control is
solid, the 20% is suggestive); adoption demand for agentic payments at the pace
assumed.

**Alternatives considered and rejected.**

- **Scoped bearer tokens** (OAuth-style) — the incumbent. Rejected: does not bind
  to a transaction; forgeable by the key holder.
- **Mandate/delegation credentials** — closer, but typically a smaller-blast-radius
  bearer credential, still not transaction-bound. `delegated_mandate` is a named
  *weaker* method here, not the default.
- **A learned/model-based authorisation control** — rejected outright: no
  probabilistic control belongs on the authorisation path; the guarantee must be
  deterministic and explainable.
- **Enforcing single-use in the library** — impossible without owning the host's
  transaction; hence the `Store` contract + conformance suite.

---

# PART V — PROCESS AND FORWARD

## 28. Full process documentation (advisory)

The development followed: hypothesis → design → extraction → conformance-suite
construction → self-test against broken stores → PostgreSQL reference store →
workload benchmark → red-team → remediation → specification-alignment →
publication. Each stage produced a concrete artefact (file, test, vector, result
JSON, or fixed finding), and each failure (§4, §22) was recorded rather than
quietly corrected. The intended reproducible process for an adopter is the reverse
telescope: read the SPEC, implement a `Store`, run the conformance suite until
green, wire the verifier at the point money moves, and hold the whole to the
"what is checkable" table.

## 29. Fallbacks

- **If an adopter's storage cannot make `Write` run inside `Consume`'s
  transaction**, the suite fails — the fallback is not to weaken the check but to
  learn that the storage cannot offer the guarantee, and to change it before
  launch.
- **If key rotation is needed before v2**, the documented fallback is to trust both
  keys during an overlap window longer than the maximum lifetime.
- **If a licensed screening/policy layer is required**, it is orthogonal and
  provided by the adopter; the primitive does not block on it.
- **If third-party audit is unavailable before a needed deployment**, the fallback
  is an explicit, written acceptance of the residual risk by the deploying
  authority — never a silent proceed.

## 30. Actionable next steps

**Immediate (0–2 weeks):** publish this manuscript alongside the repo; add a
LICENSE (author's choice of MIT/Apache-2.0/proprietary); a third-language vector
reproduction (TypeScript) to strengthen O2.

**Short-term (1 quarter):** a first external adopter runs the conformance suite in
their CI (O1); a managed-issuer reference (HSM/KMS custody) behind the issuer
interface; property-based/fuzz tests over the digest and verifier.

**Medium-term (2–3 quarters):** commission the independent security audit (O3);
ship key rotation (O5, v2); a production reference deployment behind a
sponsor/EMI, moving real funds with observability (O4).

**Ongoing:** keep the vectors pinned and CI green; keep the red-team record public;
re-run the workload study on new hardware; keep the "not claimed" section honest as
capabilities change.

## 31. What was bad, the failures, the decisions, and why it matters

**What was bad / the failures** (recorded, not hidden): a conformance suite that
passed a broken store one run in five; a single broken store that could not
exercise every check; a receipt integrity method that affirmed a receipt showing
the wrong money; a verifier that accepted arbitrary method strings; a benchmark
whose contention test had no concurrency in it and whose control cohort silently
measured zero; a "super-linear scaling anomaly" that was single-run noise; a
connection pool configured above the server's limit. Every one is documented here
or in the repo's history.

**Key decisions:** make single use the host's `Store`, not the library's (correct,
and the source of the conformance-suite contribution); verify the signature
*before* trusting the payload, and the binding *before* consuming; use the binding
digest as the authenticator challenge; keep the core dependency-free and the
PostgreSQL store a separate module; open the trust substrate and commercialise the
operations.

**Challenges:** proving a *transactional* property in someone else's database
without owning it; making a concurrency test deterministic; measuring a null
result trustworthily; extracting a primitive without losing the properties that
made it worth extracting.

**Why it matters:** money movement is the highest-consequence place to get
authorisation wrong, and it is precisely where non-deterministic agents are now
being placed. A primitive that makes "a human authorised *this exact* payment,
once" a *checkable fact* rather than a promise — and that makes an adopter's
correctness *decidable by running a suite* — is a public-good safety component and
a commercial wedge at the same time.

**Future works / future-proofing:** version is inside the digest, so the format
can evolve without ambiguity; the verifier holds a per-issuer key map, so trust
can expand without widening existing authority; the `context` field lets adopters
bind facts the format does not model without forking it; the conformance suite
means new implementations (new languages, new databases) can prove themselves
against the same contract. Planned: key rotation, additional language
reimplementations, an independent audit, and a production reference.

---

## Appendix A — Artefact map

`authority.go` (binding digest, mint, verify) · `store.go` (Store contract,
Authorise) · `receipt.go` (evidence) · `conformance/` (suite + self-test) ·
`memory/`, `postgres/` (reference stores) · `bench/`, `notebooks/` (workload) ·
`testdata/` (10 vectors + Python reimplementation) · `SPEC.md` (normative) ·
`ADOPTION.md` (integration) · `ARCHITECTURE.md` (system design).

## Appendix B — Citation

> Van Laarhoven, F. A. (2026). *BoundedAuth: a transaction-bound, single-use
> authorisation credential for money movement.* Software artefact and engineering
> research manuscript. ORCID 0009-0006-8931-0364.
> https://github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI
