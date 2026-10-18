# CLAUDE.md, working instructions for keyryx

Process and invariants only. **No status**: status goes stale, and a stale
instruction file is worse than none. For where the code is, read the tests and
`README.md`'s NOT PROVEN section.

## What this is

Key custody and an independent witness for the agent-governance record of the
TAIPANBOX stack. `@decided 2026-10-18`: a service of its own, public, written
in Go, off every request path, owning the custody and rotation of signing keys
and an independent witness of the record.

Two roles in one binary, never in one process:

- **custody** holds keys, signs low-rate statements on request (approval
  tokens, record seal roots, audit manifests), certifies the short-lived keys
  of high-rate signers (the delegation service's token key, each producer's
  stream checkpoint key) and publishes key sets with overlap;
- **witness** reads the record read-only, checks that what it saw before is
  still there, countersigns what it sees, and keeps its own append-only log.

It is defensive. It exists so an organisation can prove what its own agents and
planes did and that nobody rewrote it afterwards. Never describe it, in code,
docs or commit messages, as tooling for acting against anyone else.

## Read before you change anything

1. `README.md`, and specifically NOT PROVEN.
2. The invariants below, and the "What must never be added" list.
3. For anything that touches a key: RFC 7638 (thumbprints), RFC 7515/7517
   (JWS, JWK), FIPS 186-5 (ECDSA), FIPS 204 (ML-DSA), RFC 9162 (Merkle trees
   for append-only logs). When the code and a standard disagree, the standard
   wins and the code is the bug.

## Invariants

1. **Never on a request path.** No enforcement point, policy decision or agent
   call waits on this service. Verifiers cache what it publishes and keep
   verifying when it is down; the only synchronous calls are human-rate or
   schedule-rate (an approval being granted, a seal, a manifest asked for, a
   key renewal). *(not enforced by a gate yet: held by review; the custody
   pull request names every route and what calls it)*

2. **No decisions.** It signs what a consumer that was granted a key asks it
   to sign. It evaluates no policy, refuses nothing for money and judges no
   tool call. *(held by review)*

3. **No agent identity is issued here.** The delegation service issues agent
   credentials; this service certifies that service's signing key and never an
   agent. *(held by review)*

4. **No provider key is held here.** A model or tool provider's key is a
   credential to spend, held by the gateway that spends it; moving it here
   would put this service on the request path. *(held by review)*

5. **No private key leaves.** No route, log line, event or file outside the
   wrapped key store carries a private member, and the store holds private keys
   only wrapped under the root key. *(not built yet: the custody pull request
   adds the store and a gate over its routes)*

6. **A role that cannot do its job refuses to start.** A key service that came
   up holding nothing would answer and sign nothing, which reads as working; one
   that came up with a default key would sign anything. Exit code 2, and the
   message names what is missing. *(test: `TestARoleThatIsNotBuiltRefusesToStart`,
   `TestTheBuiltBinaryRefusesARoleItDoesNotBuild`)*

7. **Custody and witness never share a process, a key, a uid or a data
   directory.** A compromise of custody gives the power to sign; the witness,
   which saw what was there before, is what then disagrees, and it can only if
   custody cannot reach its key or its log. *(not built yet: held by the
   witness pull request and by the launchers' wiring gates)*

8. **The standard library first; every dependency argued.** `crypto/ecdsa`,
   `crypto/mldsa`, `crypto/aes`, `crypto/hkdf`, `net/http` cover what this
   service does. A third-party module is argued in the pull request that adds it
   and recorded with its reason in `DEPENDENCIES.md`. *(gate:
   `scripts/dependencies-are-argued.sh`)*

9. **What this repository contributes to a stack is declared and proved by
   running.** `components.json`: everything under `checked` is asserted by
   `internal/manifest` (the binaries built, the variables read, the refusal
   exit code of the built binary); everything under `declared` carries its own
   `why`. *(tests: `TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse`,
   `TestEveryEnvironmentVariableThisRepositoryReadsIsDeclaredAndTheReverse`,
   `TestEveryDeclaredEntryCarriesItsReason`,
   `TestTheBuiltBinaryRefusesARoleItDoesNotBuild`)*

10. **No quote of the owner and no attribution by name in any tracked file.**
    This repository is public. A decision is recorded as `@decided YYYY-MM-DD`
    and a paraphrase in English, never edited afterwards. *(gate:
    `scripts/no-owner-quotes.sh`)*

11. **No long dash in any tracked file.** Use a comma, a colon, parentheses or a
    short hyphen. *(gate: `scripts/no-long-dashes.sh`, which proves itself with
    `--prove`)*

12. **Every base image is pinned by digest.** *(gate:
    `scripts/base-images-pinned-by-digest.sh`)*

13. **Every scenario names a test and every named test exists.** *(gate:
    `scripts/features-are-bound.sh`)*

14. **The numbers the README states are true.** *(gate:
    `scripts/readme-numbers.sh`)*

15. **Every gate fails on its own fault and passes on what it must not catch,
    and says "measured nothing" when its subject is gone.** *(gate:
    `scripts/gates-have-teeth.sh`, which also refuses a gate in `scripts/`
    that has no case)*

## What must never be added without a conversation

- **A route on any request path**: anything a door, a policy decision point or
  an agent calls per call (invariant 1).
- **A decision**: a policy, an allow or a deny of anything but the use of a key
  by the consumer it was granted to (invariant 2).
- **Agent identity issuance** (invariant 3) and **provider keys** (invariant 4).
- **A metered dependency**: a cloud KMS client, a paid time-stamping authority,
  object storage with retention, or anything else that costs money to run, until
  the owner's decision is recorded first. A KMS adapter is a later option the
  owner decides on, not a default.
- **Any path that returns, logs or serialises a private key** outside the wrapped
  store (invariant 5).
- **A sign route for a key the caller was not granted**, or a key set that still
  publishes a revoked key id.
- **Custody and witness in one process** (invariant 7).

## Tier

**T3** for anything touching a key, a signature, a statement format, the store,
consumer authentication or the witness log: a wrong answer there is silent. That
means scenarios first, every new test red first against the unfixed code,
mutation testing of the product code with each mutant named beside the test
that caught it, and a gate with teeth where the rule is structural.

## Gates

```sh
test -z "$(gofmt -l .)"
go vet ./...
staticcheck ./...
go test -race ./...
go build ./...
./scripts/features-are-bound.sh
./scripts/readme-numbers.sh
./scripts/base-images-pinned-by-digest.sh
./scripts/dependencies-are-argued.sh
./scripts/no-owner-quotes.sh
./scripts/no-long-dashes.sh
./scripts/gates-have-teeth.sh   # needs a clean tree; run it after committing
```

CI also runs `govulncheck ./...` and `gosec -quiet ./...` in its `security`
job. A finding is fixed or argued in the pull request; a `#nosec` carries its
rule and its reason on the same line.

## Working loop

1. Branch off `main`, one logical increment per branch.
2. Scenarios first (`features/*.feature`, each bound to a test by
   `# @test:<TestName>`), then the tests, red first, then the code.
3. Every gate above passes; the teeth run after committing.
4. Conventional Commits; the co-author trailer names the model that did the
   work.

## Distribution

Published as `ghcr.io/taipanbox/keyryx` by `.github/workflows/release.yml` on a
`v*` tag push: static, distroless, non-root, `linux/amd64` and `linux/arm64`,
signed keyless with cosign by digest, an SBOM and a build-provenance attestation
attached. No moving tag (`:latest`, `:main`) is ever published. The version the
binary reports (`main.version`) is stamped from the tag at build time.
