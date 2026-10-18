<div align="center">

# keyryx - key custody and a witness for the record

**Keys that never sit beside the code that uses them, and somebody outside the
writers who saw the record when it was written.**

[![CI](https://github.com/TAIPANBOX/keyryx/actions/workflows/ci.yml/badge.svg)](https://github.com/TAIPANBOX/keyryx/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/go-1.27-00ADD8.svg)
![tests](https://img.shields.io/badge/tests-153-brightgreen.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Status](https://img.shields.io/badge/runtime%20dependencies-2-blue.svg)

</div>

Part of the TAIPANBOX agent-governance stack. Two roles in one binary, never in
one process:

- **custody** holds signing keys and signs low-rate statements on request
  (human approval tokens, record seal roots, audit manifests); certifies the
  short-lived keys of high-rate signers (the delegation service's token key, each
  producer's stream checkpoint key); publishes key sets with an overlap, so a
  rotation is never an outage.
- **witness** reads the record read-only, checks that every byte it saw
  before is still there, attests to what it sees, and keeps its own
  append-only Merkle log, its tree heads signed with ECDSA P-384 and ML-DSA-65
  side by side, so what it signed today still verifies after classical
  signatures are retired.

## What it is not

- **Not on any request path.** No enforcement point waits on it to decide
  anything. Verifiers cache what it publishes and keep verifying when it is down.
- **Not a decision point.** It signs what a consumer that was granted a key asks
  it to sign, and judges nothing else.
- **Not an identity provider for agents**, and **not a holder of provider keys**.
- **Not a metered service.** Nothing in it calls a paid API. A cloud key
  management adapter is a later option, decided by the operator, never a default.

## Status

**Both roles are built.** `keyryx custody` holds keys, signs on request for
the consumers its policy grants a key, certifies the short-lived keys
high-rate signers hold themselves, and publishes each key's set with an
overlap. `keyryx witness` reads the bus, its checkpoints and trailryx's
sealed manifests, says when anything it saw is no longer there, attests to
each new trailryx store root, and keeps its own signed log. `keyryx verify`
checks a witness log, or streams and their checkpoints, offline.

```bash
go build -o keyryx ./cmd/keyryx
./keyryx version
KEYRYX_DATA=/var/lib/keyryx KEYRYX_ROOT_KEY_FILE=/run/secrets/keyryx-root \
  KEYRYX_POLICY=/etc/keyryx/policy.json ./keyryx custody
KEYRYX_WITNESS_DATA=/var/lib/keyryx-witness KEYRYX_WITNESS_ROOT_KEY_FILE=/run/secrets/keyryx-witness-root \
  KEYRYX_WITNESS_EVENTS=/var/lib/agent-stack/events ./keyryx witness
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
- **A state MAC on every record**, under another key derived from the root
  key: a key's state (active, next, retired, revoked) and its dates, and a
  statement's revocation, are custody's own word. A record whose MAC does not
  hold is treated as revoked, never published or used, and raises an alarm:
  on stderr and on the use log at every start, and in `GET /v1/state`, until
  an admin revokes the key it names.
- **A delegation root**, two keys of one generation, ES384 and ML-DSA-65, in
  the store's reserved `keyryx.` name space. It signs key statements and
  nothing a request chose.
- **Key statements**, one file per certified key under
  `KEYRYX_DATA/statements/<name>/`, each verified under the root at every
  start. Custody never holds a delegated key's private half.
- **A use log**, `KEYRYX_DATA/use.ndjson`: one line per signature, key
  statement, rotation and revocation, each naming the SHA-256 of the line
  before it. A signature or a statement is answered only after its line reached
  the disk. The log holds the digest of what was signed, never the statement.

### The surface

| route | who | what |
|---|---|---|
| `GET /healthz` | anyone | liveness |
| `GET /v1/state` | anyone | the role, the version, each key's active and next key id, and `alarms`: every state on disk custody could not vouch for |
| `GET /v1/keys` | anyone | the inventory: every key id, its algorithm, its state and its dates, revoked ones included; never a private member |
| `GET /v1/jwks/{name}` | anyone | the key set a verifier caches: for a held key its active, next and retired keys; for a delegated name every key certified for it up to its `not_after` plus the overlap; for `keyryx.delegation-root` both halves of the root; never a revoked key |
| `GET /v1/statements/{kid}` | anyone | `{"statement", "revoked_at"}`: the statement that certified a delegated key, and when it was revoked (0 when it was not) |
| `POST /v1/keys/{name}/sign` | a consumer granted `sign` on `{name}` | body `{"statement_b64", "purpose"}`, a statement of at most 4 KiB; answer `{"alg", "kid", "signature_b64", "public_key_b64"}` |
| `POST /v1/keys/{name}/challenge` | a consumer granted `delegate` on `{name}` | answer `{"challenge", "expires_at"}`: random, for this consumer and name, answerable once within a minute |
| `POST /v1/keys/{name}/delegate` | a consumer granted `delegate` on `{name}` | body `{"jwk", "challenge", "proof_b64", "lifetime_s"}`; answer `{"statement", "kid", "not_before", "not_after"}` |
| `POST /v1/keys/{name}/rotate` | an admin key | creates the next key, published now, signing after `KEYRYX_PUBLISH_AHEAD`; for `keyryx.delegation-root`, both halves together |
| `POST /v1/kids/{kid}/revoke` | an admin key | takes a key id out of every key set at once, held or delegated; revoking the active held key promotes the next one, or makes a fresh one |

ECDSA signatures are fixed-width `R || S` over SHA-256 (ES256) or SHA-384
(ES384), as in JWS. Key ids are RFC 7638 thumbprints for EC keys and
`mldsa65:` with the base64url SHA-256 of the public key for ML-DSA. A refusal
answers its status and nothing else; the reason is in the operator's log.

### Delegated keys

A high-rate signer (the delegation service's token key, a producer's stream
checkpoint key) generates its own key and keeps it in memory. To have it
certified:

1. it asks `POST /v1/keys/{name}/challenge`;
2. it signs, with the key being certified, the bytes
   `keyryx/delegate/v1 NUL <name> NUL <consumer> NUL <kid> NUL <challenge>`
   (`kid` the key's RFC 7638 thumbprint; ES256 or ES384, `R || S`);
3. it sends `POST /v1/keys/{name}/delegate` with its public JWK, the
   challenge, that proof and the life it wants, from ten minutes to the name's
   `max_lifetime`.

The answer is a **key statement**: a JWS in the General JSON Serialization,
one payload and exactly two signatures, the ES384 and the ML-DSA-65 halves of
the delegation root. The payload's claims are `v` (1), `iss` (`keyryx`),
`name`, `owner` (the consumer), `kid`, `jwk`, `not_before`, `not_after`,
`issued_at`, `jti` and `roots` (both halves' key ids), all required and no
other accepted. The ES384 half is also a compact JWS
(`protected.payload.signature`) any ES384 verifier checks against
`/v1/jwks/keyryx.delegation-root`.

The key is then in `/v1/jwks/{name}` until its `not_after` plus the name's
overlap. A renewal asked while another key of the name is still valid a
publish-ahead time from now starts that time later, so a verifier that caches
the key set holds the new key before it signs anything. A key id is certified
once; a revoked one is never published or certified again, and neither is a
key certified under a root key since revoked. At most four keys of one name
are live at once.

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
| `KEYRYX_PUBLISH_AHEAD` | no | how long a next key, or a renewed delegated key, is published before it signs; default `15m`, one minute to one day |

Anything missing or malformed refuses the start with exit 2 and names the
variable. The policy file:

```json
{
  "version": 1,
  "keys": [
    {"name": "wardryx-approval", "alg": "ES256"},
    {"name": "trailryx-root", "alg": "ML-DSA-65"},
    {"name": "vouchryx-token", "alg": "ES256", "mode": "delegated",
     "max_lifetime": "72h", "overlap": "10m"}
  ],
  "consumers": [
    {"name": "wardryx", "auth": {"socket": "wardryx"},
     "grants": {"wardryx-approval": ["sign"]}},
    {"name": "record-seal", "auth": {"key_digest": "sha256:<64 hex>"},
     "grants": {"trailryx-root": ["sign"]}},
    {"name": "vouchryx", "auth": {"key_digest": "sha256:<64 hex>"},
     "grants": {"vouchryx-token": ["delegate"]}}
  ]
}
```

A key is `held` (the default: custody holds it and signs with it) or
`delegated` (ES256 or ES384; custody certifies a key its consumer holds, for
at most `max_lifetime`, from ten minutes to a week, and publishes it for
`overlap` after, default ten minutes). An unknown field, a duplicate, a grant
of an undeclared key, `sign` on a delegated key or `delegate` on a held one,
a name starting `keyryx.`, or a consumer with no way in or two refuses the
start.

## The witness

A separate process, with its own data directory, its own root key and its
own key: the witness refuses custody's directory, key file or key as its own.
Every `KEYRYX_WITNESS_INTERVAL` it reads, read-only:

- **every stream** (`*.ndjson`) in `KEYRYX_WITNESS_EVENTS`. It keeps the bytes
  it has read and their SHA-256, the same `prefix` as agent-passport SPEC
  6.5.1, because the SPEC 6.5 chain hash leaves `prev_hash` out and a line
  rewritten with its successor re-linked passes the chain. Each interval it
  hashes the stream again from byte zero, so any byte it saw that changed is
  `witness_stream_rewritten`; a stream that holds fewer bytes than it saw is
  `witness_stream_truncated`; a new chain mid-stream is
  `witness_chain_restarted`, medium when a `resume` checkpoint explains it.
- **every checkpoint file** in `KEYRYX_WITNESS_CHECKPOINTS`, by SPEC 6.5.1's
  steps: each record its own RFC 8785 form, signed by a key whose statement
  custody serves (`KEYRYX_WITNESS_CUSTODY_URL`), valid at the record's time,
  not revoked when the witness read it, and certified for the key name that
  stream is bound to (`KEYRYX_WITNESS_STREAM_KEYS`), and every checkpoint it
  kept still holding. A record that does not is `witness_checkpoint_invalid`;
  an unsigned one is `witness_checkpoint_unsigned`; while custody does not
  answer, a record waits. Statements verify only under the delegation root
  the witness pinned in its own log when it first read it: a different set
  served later is a high `witness_checkpoint_invalid` about the
  `delegation-root`, and is not used until an operator pins it.
- **every trailryx data directory** in `KEYRYX_WITNESS_RECORDS`. It computes
  the store root as trailryx-verify does and attests to each new one in
  trailryx-sign's `witness_statement` bytes with its ES384 half, written to
  `KEYRYX_WITNESS_DATA/attestations/<tenant>/<root>.json`. A sealed manifest
  rewritten or gone is `witness_root_equivocated`; a record that grew past a
  seal's worth with no new root for two seal intervals is `witness_root_missing`.

Every finding is an agent-event in `KEYRYX_WITNESS_ALERTS` (by default
`keyryx.ndjson` in the events directory), source `keyryx`, subject
`agent://keyryx.internal/witness`, with counts and clipped hashes and never
record content. Every observation is an entry in its own log
(`log.ndjson`), an RFC 9162 Merkle tree over SHA-384, and each interval ends
with a tree head signed by ES384 and ML-DSA-65 (`heads.ndjson`). When an
operator names an RFC 3161 time-stamping authority, the latest head is
time-stamped every `KEYRYX_WITNESS_TSA_EVERY` and the token goes into the log.

| witness route | what |
|---|---|
| `GET /healthz` | liveness |
| `GET /v1/witness/head` | the latest signed tree head |
| `GET /v1/witness/keys` | the witness key's two halves, the key set its heads and attestations verify under |
| `GET /v1/witness/inclusion?index=I&size=N` | the leaf at I and its RFC 9162 inclusion proof in the tree of size N |
| `GET /v1/witness/consistency?first=M&second=N` | the RFC 9162 proof that the tree of size N extends the one of size M |
| `GET /v1/witness/entries?start=S&end=E` | the entries S to E, at most 1000 |

| variable | required | what |
|---|---|---|
| `KEYRYX_WITNESS_DATA` | yes | the witness's own data directory, mode 0700, never custody's |
| `KEYRYX_WITNESS_ROOT_KEY_FILE` | yes | its own root key file, never custody's or a copy of custody's key |
| `KEYRYX_WITNESS_EVENTS` | yes | the bus directory it reads |
| `KEYRYX_WITNESS_CHECKPOINTS` | no | the checkpoint directory it reads |
| `KEYRYX_WITNESS_CUSTODY_URL` | once checkpoints are set | where custody serves key statements |
| `KEYRYX_WITNESS_STREAM_KEYS` | once checkpoints are set | `stream.ndjson\|key-name` per stream, comma or line separated: the delegated key name whose certified keys sign that stream's checkpoints |
| `KEYRYX_WITNESS_DELEGATION_ROOT_PIN` | no | the delegation root's kids, at least one ES384 and one ML-DSA-65, comma separated; replaces the pin in the log. Unset, the first set custody serves is pinned |
| `KEYRYX_WITNESS_ALERTS` | no | where it writes its findings; default `<events>/keyryx.ndjson` |
| `KEYRYX_WITNESS_RECORDS` | no | `tenant\|directory` per trailryx data directory, comma or line separated |
| `KEYRYX_WITNESS_ADDR` | no | default `127.0.0.1:4341` |
| `KEYRYX_WITNESS_INTERVAL` | no | default `1m`, one second to one hour |
| `KEYRYX_WITNESS_FULL_BYTES` | no | a stream over this many bytes is hashed from zero only every `KEYRYX_WITNESS_FULL_INTERVAL`; default 256 MiB |
| `KEYRYX_WITNESS_FULL_INTERVAL` | no | default `1h` |
| `KEYRYX_WITNESS_SEAL_EVERY` and `KEYRYX_WITNESS_SEAL_LINES` | no | what a seal's worth is, for `witness_root_missing`; default `15m` and 4096 lines |
| `KEYRYX_WITNESS_NAME` | no | the name in its attestations; default `keyryx-witness` |
| `KEYRYX_WITNESS_TSA_URL` | no | an https RFC 3161 authority; unset, none is called |
| `KEYRYX_WITNESS_TSA_CA` | once a TSA is set | the PEM root its tokens must chain to |
| `KEYRYX_WITNESS_TSA_EVERY` | no | default `1h`, ten minutes to a day |

### Checking offline

```bash
# the witness's log, against the key set it published
keyryx verify log --dir /var/lib/keyryx-witness --keys witness-keys.json
# streams and their checkpoints, against saved statements and the delegation root
keyryx verify streams --events events/ --checkpoints checkpoints/ \
  --statements statements/ --stream-keys 'wardryx.ndjson|wardryx-stream' \
  --roots delegation-root.json
```

Each check prints `[ok]`, `[weak]` or `[broken]`, and the last line says
`VERIFIED` (exit 0) or `NOT VERIFIED` (exit 1). An empty directory is
"measured nothing", never OK. `statements/` holds one `<kid>.json` per key,
each what `GET /v1/statements/{kid}` answered.

## Testing

153 tests. Tier T3: these are key and signature decisions where a wrong answer
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

- **trailryx does not attach the attestations yet.** `trailryx-node` takes no
  witness input, so the attestations the witness writes are files beside its
  log until trailryx reads them into its packs; `trailryx-verify` would check
  them as it checks any witness, which this repository has not run.
- **The store root is trailryx's construction rebuilt by hand.** It is
  checked against trailryx's source at 92dd4b6 by a reference written
  separately in the tests, not against a store trailryx itself sealed: no
  trailryx build has run here.
- **A rewrite that also shortens a stream is reported as a truncation.** The
  witness knows the bytes are not the ones it saw; with fewer bytes than it
  read, it names the shrinking.
- **The cost of re-reading is not measured.** Each interval hashes every
  stream under `KEYRYX_WITNESS_FULL_BYTES` from byte zero; how long that takes
  on a real bus has not been measured.
- **No time-stamping authority has been asked.** The RFC 3161 client is
  tested against an authority the tests build, with ECDSA and RSA keys; no
  public authority's token has been verified by it.
- **The first root is taken on first use.** With no
  `KEYRYX_WITNESS_DELEGATION_ROOT_PIN`, the witness pins whatever root set
  custody serves at its first read; a set swapped before that read is pinned.
  An operator closes that window by setting `KEYRYX_WITNESS_DELEGATION_ROOT_PIN`
  from the kids of the delegation root's published key set before the witness
  first starts. A real
  rotation of the delegation root reads as a changed root until an operator
  pins the new set, and no rotation has been run against a witness here.
- **The witness reads the bus and the record, not custody's use log**, and
  custody writes no `key_rotated` or `key_revoked` event yet.
- **Nothing consumes a key statement yet.** The delegation service, the
  producers' checkpoint writers and the shared key client that would ask for
  and renew delegated keys are later pull requests in their own repositories;
  the round trip with the estate's shared verifier is tested here, not run by
  a consumer.
- **An earlier record can be put back.** The state MAC proves custody wrote a
  state, not that it is the latest one: whoever can write the data directory
  can restore a copy of a record from before its revocation, and that copy's
  MAC holds. The use log keeps the revocation line, and the witness is what
  would notice.
- **Challenges live in memory.** A restart drops the outstanding ones, and the
  consumer asks again.
- **A late renewal can sign before verifiers refresh.** When a name's current
  key ends inside the publish-ahead time, the new key is valid at once, since
  waiting would leave no valid key at all.
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
  from its first line.** The witness of this version does not read it.
- **No cloud key management.** The root key is a file. A KMS adapter would be
  metered, and it is the operator's decision, not a default.
- **No image has been published.** The release workflow builds and signs one on
  the first `v*` tag; until then there is nothing to pull.
- **Independence from a host administrator** will not come from this service
  alone: on one machine the witness is a separate user and volume, not a
  separate trust domain. An off-host anchor (a public time-stamping authority,
  built here and off by default, or a second witness on another machine, not
  built) is what closes that, and it is the operator's to switch on.
- **Post-quantum signatures** are produced with Go 1.27's `crypto/mldsa`; no
  verifier outside this repository checks ML-DSA yet, and the key set's AKP
  form follows a JOSE draft, not a published RFC.

## Licence

Apache-2.0, like the rest of the stack. See [LICENSE](./LICENSE).
