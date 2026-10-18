# Dependencies

This service holds signing keys, so the Go standard library is the first
choice for everything it does: `crypto/ecdsa`, `crypto/mldsa` (FIPS 204, Go
1.27), `crypto/aes` and `crypto/cipher`, `crypto/hkdf`, `crypto/sha256`,
`crypto/sha512`, `net/http`, `encoding/json`. A third-party module is a
decision argued in the pull request that adds it, then recorded in the table
below with its reason. `scripts/dependencies-are-argued.sh` refuses a
`require` line that has no row here (CLAUDE.md invariant 8).

No metered dependency is added without the owner's decision recorded first: a
cloud KMS client is one (CLAUDE.md, "What must never be added").

| module | why it is here |
|---|---|
