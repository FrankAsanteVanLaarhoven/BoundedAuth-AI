# Security policy

BoundedAuth is an authorisation primitive for money movement. A vulnerability
here can let a payment be authorised that a human never signed, so reports are
taken seriously and handled privately until a fix is available.

## Reporting a vulnerability

**Do not open a public issue for a security report.**

- Use GitHub's **private vulnerability reporting** (repository → *Security* →
  *Report a vulnerability*), or
- email **frankleroyvan@gmail.com** with `BoundedAuth security` in the subject.

Please include: the version or commit, a description of the issue, and — where
possible — a minimal reproduction or a failing test against the property you
believe is broken (forgery, repointing, replay, single-use/atomicity, or a
receipt that describes a different payment than was authorised).

## What to expect

- **Acknowledgement:** within 3 working days.
- **Assessment:** an initial severity assessment and whether it is accepted,
  within 10 working days.
- **Fix and disclosure:** coordinated. A fix and an advisory are prepared before
  public disclosure; we will agree a timeline with you and credit you unless you
  prefer to remain anonymous.

## Scope

In scope: the credential and receipt properties the library claims — signature
verification, transaction binding, lifetime enforcement, the closed method set,
single-use atomicity as exercised by the conformance suite, and receipt
integrity/`MatchesAuthority`.

Out of scope (documented limitations, not vulnerabilities): a compromised
**issuer** minting authority; a compromised **host** performing effects with no
credential; and the absence of key rotation in v1. These are stated in the
README's *Security model* and *Not claimed* sections.

## Supported versions

Pre-1.0: only the latest tagged release (and `main`) receive security fixes.
