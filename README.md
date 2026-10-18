<div align="center">

# keyryx - key custody and a witness for the record

**Keys that never sit beside the code that uses them, and somebody outside the
writers who saw the record when it was written.**

[![CI](https://github.com/TAIPANBOX/keyryx/actions/workflows/ci.yml/badge.svg)](https://github.com/TAIPANBOX/keyryx/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/go-1.27-00ADD8.svg)
![tests](https://img.shields.io/badge/tests-7-brightgreen.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Status](https://img.shields.io/badge/runtime%20dependencies-0-blue.svg)

</div>

Part of the TAIPANBOX agent-governance stack. Two roles in one binary, never in
one process:

- **custody** holds signing keys and signs low-rate statements on request
  (human approval tokens, record seal roots, audit manifests); certifies the
  short-lived keys of high-rate signers (the delegation service's token key, each
  producer's stream checkpoint key); publishes key sets with an overlap, so a
  rotation is never an outage.
- **witness** reads the record read-only, checks that what it saw before is
  still a prefix of what it sees now, countersigns what it sees, and keeps its
  own append-only Merkle log, its tree heads signed with ECDSA P-384 and ML-DSA-65 side
  by side, so what it signed today still verifies after classical signatures are
  retired.

## What it is not

- **Not on any request path.** No enforcement point waits on it to decide
  anything. Verifiers cache what it publishes and keep verifying when it is down.
- **Not a decision point.** It signs what a consumer that was granted a key asks
  it to sign, and judges nothing else.
- **Not an identity provider for agents**, and **not a holder of provider keys**.
- **Not a metered service.** Nothing in it calls a paid API. A cloud key
  management adapter is a later option, decided by the operator, never a default.

## Status

This is the scaffold: the repository, its gates, its CI and its release
workflow. **Neither role is built yet.** `keyryx custody` and `keyryx witness`
refuse to start (exit 2) rather than come up holding nothing; `keyryx version`
prints the build.

```bash
go build -o keyryx ./cmd/keyryx
./keyryx version
./keyryx custody   # refuses: the custody role is not built in this version
```

## Testing

7 tests. Tier T3: once the roles land, these are key and signature decisions
where a wrong answer is silent, so every new test is red first and the product
code is mutation-tested.

```bash
go test ./... -race
go vet ./...
staticcheck ./...
./scripts/features-are-bound.sh
./scripts/readme-numbers.sh
./scripts/base-images-pinned-by-digest.sh
./scripts/dependencies-are-argued.sh
./scripts/no-owner-quotes.sh
./scripts/no-long-dashes.sh
./scripts/gates-have-teeth.sh    # needs a clean tree
```

## NOT PROVEN

Stated here rather than left to be discovered.

- **Nothing this service exists for is built yet.** No key is held, nothing is
  signed, nothing is witnessed. Every property in the description above is a
  design, not a measurement.
- **No image has been published.** The release workflow builds and signs one on
  the first `v*` tag; until then there is nothing to pull.
- **Independence from a host administrator** will not come from this service
  alone: on one machine the witness is a separate user and volume, not a
  separate trust domain. An off-host anchor (a public time-stamping authority, or
  a second witness on another machine) is what closes that, and it is opt-in.
- **Post-quantum signatures** will be produced with Go 1.27's `crypto/mldsa`;
  no verifier outside this repository checks ML-DSA yet.

## Licence

Apache-2.0, like the rest of the stack. See [LICENSE](./LICENSE).
