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
| `github.com/TAIPANBOX/agent-stack-go` | The estate's shared token library, public and under the same organisation. Custody uses only its `delegation` package: `VerifyToken` checks a Kubernetes projected service-account token with the algorithm taken from the key's own type, never from the token's header (so `none`, HMAC and a downgrade are refused in one audited place), `Thumbprint` computes RFC 7638 key ids, and `FromPublic` renders an EC public key as a JWK with public members only. The delegation service and the gateways verify with the same code, so a fix to it lands once for every verifier. Writing a second JWS verifier here would be a second place for the alg-confusion defence to be wrong. Module graph pruning keeps its own requirements (`gowebpki/jcs`, `santhosh-tekuri/jsonschema`) out of this build: `go.sum` lists the one module. |
