# Security Policy

keyryx holds signing keys and witnesses the record of the TAIPANBOX
agent-governance stack: it signs low-rate statements on request, certifies the
short-lived keys of high-rate signers, and keeps an append-only log of what the
record held and when. A weakness here is a weakness in the evidence every other
service relies on, so reports are welcome and taken seriously.

## Reporting a vulnerability

Please report security issues privately, not in public issues or pull
requests: open a GitHub private security advisory at
<https://github.com/TAIPANBOX/keyryx/security/advisories/new>. Include the
affected version or commit, a description and a minimal reproduction. We aim to
acknowledge within a few days and to fix high-severity issues before any public
disclosure, with coordinated disclosure within 90 days of the report. There is
no bug-bounty programme; reporters are credited in the advisory unless they
prefer otherwise.

## Supported versions

Before this repository's 1.0, only `main` is supported: fixes land on `main` and
are not backported. From its 1.0 tag, the newest minor gets every fix and the
previous minor gets security-relevant fixes for 90 days after the newer one is
tagged.

## Verifying a build

Every change passes the repository's gates before merge: `go build ./...`,
`go vet ./...`, `gofmt -l .`, `staticcheck ./...`, `go test ./... -race`,
`./scripts/features-are-bound.sh`, `./scripts/readme-numbers.sh`,
`./scripts/base-images-pinned-by-digest.sh`,
`./scripts/dependencies-are-argued.sh`, `./scripts/no-owner-quotes.sh`,
`./scripts/no-long-dashes.sh`, `./scripts/gates-have-teeth.sh`,
`govulncheck ./...` and `gosec -quiet ./...`. A published image is signed by
digest, keyless:

```bash
cosign verify ghcr.io/taipanbox/keyryx:<tag> \
  --certificate-identity-regexp '^https://github.com/TAIPANBOX/keyryx/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/taipanbox/keyryx:<tag> -R TAIPANBOX/keyryx
```
