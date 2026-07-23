# Contributing to BoundedAuth

Thank you for your interest. BoundedAuth is a security primitive for money
movement, so the bar for changes is deliberately high and the review is
skeptical by design. That is not a barrier to contribution — it is the product.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Follow
[SECURITY.md](SECURITY.md) — private disclosure, coordinated fix.

## Proposing a change

1. Open an issue describing the problem before a large change, so the design can
   be discussed before code is written.
2. Fork, branch, and open a pull request against `main`.
3. Keep the change focused. One property per pull request is easier to verify
   than five.

## The rules that will not bend

- **The core stays dependency-free.** Anything needing a driver or framework
  belongs in a separate module (see `postgres/`), never in the root package.
- **Every claimed property ships with a test that fails without it.** A claim in
  a comment or the README that no test exercises is treated as a defect.
- **The conformance suite is the contract.** A change to what a store must
  guarantee is a change to `conformance/`, and it must be demonstrated to fail a
  store that lacks the guarantee before it is trusted to pass one that has it.
- **Honesty about limits.** If a change narrows what can be claimed, the
  `Not claimed` and `Security model` sections of the README are updated in the
  same pull request.

## Running the checks

```bash
go test ./... -race            # unit + conformance, under the race detector
go test -run='^$' -fuzz=Fuzz -fuzztime=30s .   # parse/verify fuzzing
python3 testdata/verify_vectors.py             # spec reimplementation vs vectors
cd postgres && BOUNDEDAUTH_TEST_DATABASE_URL=... go test ./... -race
```

A pull request is expected to pass `go test ./... -race` and to keep the
cross-language vectors reproducing.

## Sign-off (Developer Certificate of Origin)

Contributions are accepted under the project's [LICENSE](LICENSE) (Apache-2.0):
what you submit is licensed inbound under the same terms it is distributed
outbound, per Apache-2.0 §5. Certify that you have the right to submit your work
by signing off each commit under the
[Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "…"
```

The sign-off line (`Signed-off-by: Your Name <you@example.com>`) records that
certification.

## Style

Match the surrounding code: small, well-named functions; comments that explain
*why* a check exists, not *what* the line does; and a test that a reviewer can
run to see the property hold.
