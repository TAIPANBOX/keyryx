<div align="center">

# keyryx - key custody and a witness for the record

**Keys that never sit beside the code that uses them, and somebody outside the
writers who saw the record when it was written.**

[![CI](https://github.com/TAIPANBOX/keyryx/actions/workflows/ci.yml/badge.svg)](https://github.com/TAIPANBOX/keyryx/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/go-1.27-00ADD8.svg)
![tests](https://img.shields.io/badge/tests-58-brightgreen.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Status](https://img.shields.io/badge/runtime%20dependencies-1-blue.svg)

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

**Custody is built; the witness is not.** `keyryx custody` holds keys,
signs on request for the consumers its policy grants a key, and publishes each
key's set with an overlap. `keyryx witness` refuses to start (exit 2) rather
than come up witnessing nothing. Certifying the short-lived keys of high-rate
signers is the next pull request.

```bash
go build -o keyryx ./cmd/keyryx
./keyryx version
KEYRYX_DATA=/var/lib/keyryx KEYRYX_ROOT_KEY_FILE=/run/secrets/keyryx-root \
  KEYRYX_POLICY=/etc/keyryx/policy.json ./keyryx custody
```

### What custody holds

- **A root key**, 32 random bytes as 64 hex characters in a file nobody but
  its owner can read (a host file, or a Kubernetes Secret mounted with
  `defaultMode: 0400`). A file its group or other users can read refuses the
  start.
- **Keys** of three algorithms: ES256, ES384 and ML-DSA-65 (FIPS 204, Go
  1.27's `crypto/mldsa`). Each is stored as one file under
  `KEYRYX_DATA/keys/<name>/`, its private half wrapped with AES-256-GCM under a
  key derived from the root key and bound to the key's name, id and
  algorithm. A record moved, edited or swapped refuses the start.
- **A use log**, `KEYRYX_DATA/use.ndjson`: one line per signature, rotation
  and revocation, each naming the SHA-256 of the line before it. A signature is
  answered only after its line reached the disk. The log holds the digest of
  what was signed, never the statement.

### The surface

| route | who | what |
|---|---|---|
| `GET /healthz` | anyone | liveness |
| `GET /v1/state` | anyone | the role, the version, each key's active and next key id |
| `GET /v1/keys` | anyone | the inventory: every key id, its algorithm, its state and its dates, revoked ones included; never a private member |
| `GET /v1/jwks/{name}` | anyone | the key set a verifier caches: active, next and retired keys, never a revoked one |
| `POST /v1/keys/{name}/sign` | a consumer granted `sign` on `{name}` | body `{"statement_b64", "purpose"}`, a statement of at most 4 KiB; answer `{"alg", "kid", "signature_b64", "public_key_b64"}` |
| `POST /v1/keys/{name}/rotate` | an admin key | creates the next key, published now, signing after `KEYRYX_PUBLISH_AHEAD` |
| `POST /v1/kids/{kid}/revoke` | an admin key | takes a key id out of every key set at once; revoking the active key promotes the next one, or makes a fresh one |

ECDSA signatures are fixed-width `R || S` over SHA-256 (ES256) or SHA-384
(ES384), as in JWS. Key ids are RFC 7638 thumbprints for EC keys and
`mldsa65:` with the base64url SHA-256 of the public key for ML-DSA. A refusal
answers its status and nothing else; the reason is in the operator's log.

### Who is asking

Each consumer in the policy authenticates exactly one way:

- **`socket`**: a unix socket of its own, `KEYRYX_SOCKET_DIR/<socket>/keyryx.sock`.
  The operator makes that directory for the consumer, with no permission for
  other users; whoever can enter it is that consumer, and nothing sent over it
  can claim to be another.
- **`key_digest`**: a bearer key over TCP, configured as `sha256:<64 hex>` of
  the key. The service never holds the key itself and compares digests in
  constant time.
- **`k8s`**: a Kubernetes projected service-account token over TCP, verified
  against the cluster's published keys (the algorithm taken from the key, never
  from the token), for exactly this service's audience, at most an hour long,
  bound to one service account.

### Configuration

| variable | required | what |
|---|---|---|
| `KEYRYX_DATA` | yes | the data directory, mode 0700 |
| `KEYRYX_ROOT_KEY_FILE` | yes | the root key file |
| `KEYRYX_POLICY` | yes | the policy file (below), at most 1 MiB |
| `KEYRYX_ADDR` | no | where to listen over TCP; default `127.0.0.1:4340` |
| `KEYRYX_SOCKET_DIR` | once a consumer uses `socket` | the parent of each socket consumer's directory |
| `KEYRYX_K8S_ISSUERS` | once a consumer uses `k8s` | one `issuer\|audience\|jwks-file` per line or comma |
| `KEYRYX_ADMIN_KEYS` | no | comma-separated `sha256:<64 hex>` digests of admin keys; unset, rotate and revoke refuse every call |
| `KEYRYX_PUBLISH_AHEAD` | no | how long a next key is published before it signs; default `15m`, one minute to one day |

Anything missing or malformed refuses the start with exit 2 and names the
variable. The policy file:

```json
{
  "version": 1,
  "keys": [
    {"name": "wardryx-approval", "alg": "ES256"},
    {"name": "trailryx-root", "alg": "ML-DSA-65"}
  ],
  "consumers": [
    {"name": "wardryx", "auth": {"socket": "wardryx"},
     "grants": {"wardryx-approval": ["sign"]}},
    {"name": "record-seal", "auth": {"key_digest": "sha256:<64 hex>"},
     "grants": {"trailryx-root": ["sign"]}}
  ]
}
```

An unknown field, a duplicate, a grant of an undeclared key, an operation
other than `sign`, or a consumer with no way in or two refuses the start.

## Testing

58 tests. Tier T3: these are key and signature decisions where a wrong answer
is silent, so every new test is red first and the product code is
mutation-tested.

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
./scripts/private-keys-stay-in-the-store.sh
./scripts/gates-have-teeth.sh    # needs a clean tree
```

## NOT PROVEN

Stated here rather than left to be discovered.

- **The witness is not built**, and neither is the certification of
  short-lived keys. Custody signs with the keys it holds; nothing yet
  countersigns what the record holds.
- **No real Kubernetes cluster has authenticated a consumer.** The projected
  token path is tested against tokens this repository mints with the claims a
  cluster issues; it has not run against a kubelet's token.
- **The constant-time compares are not timed.** Key and admin digests are
  compared with `crypto/subtle` over every configured digest; nothing measures
  the timing.
- **A rotation or revocation whose log line fails to write still stands.** The
  answer is 503 and the key's state has changed; only a signature is withheld
  until its line is written.
- **The use log is protected against edits in its middle, not against a rewrite
  from its first line.** That is the witness's job, which is not built.
- **No cloud key management.** The root key is a file. A KMS adapter would be
  metered, and it is the operator's decision, not a default.
- **No image has been published.** The release workflow builds and signs one on
  the first `v*` tag; until then there is nothing to pull.
- **Independence from a host administrator** will not come from this service
  alone: on one machine the witness is a separate user and volume, not a
  separate trust domain. An off-host anchor (a public time-stamping authority, or
  a second witness on another machine) is what closes that, and it is opt-in.
- **Post-quantum signatures** are produced with Go 1.27's `crypto/mldsa`; no
  verifier outside this repository checks ML-DSA yet, and the key set's AKP
  form follows a JOSE draft, not a published RFC.

## Licence

Apache-2.0, like the rest of the stack. See [LICENSE](./LICENSE).
