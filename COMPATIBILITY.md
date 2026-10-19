# Compatibility

`TAIPANBOX/keyryx` promises the surface below from its 1.0 (`compat/1.0.json`, held by `scripts/compat-surface.sh` on every push). A frozen name is not removed or renamed within a major; an additive thing may appear as a minor; an experimental thing may change in any release.

Status: pre-1.0 (latest tag v0.1.2): no tag has frozen this surface yet. The surface below is what 1.0 will freeze, and scripts/compat-surface.sh holds it on every push, so the 1.0 tag freezes something the gate has already held. TestTheFrozenRoutesAreTheRouteTables holds the two route kinds against the route tables in both directions.

## Frozen

### cli.subcommands (4)

- `custody`
- `witness`
- `verify`
- `version`
- held in: `cmd/keyryx/main.go`

### env (27)

- `KEYRYX_DATA`
- `KEYRYX_ROOT_KEY_FILE`
- `KEYRYX_POLICY`
- `KEYRYX_ADDR`
- `KEYRYX_SOCKET_DIR`
- `KEYRYX_ADMIN_KEYS`
- `KEYRYX_K8S_ISSUERS`
- `KEYRYX_PUBLISH_AHEAD`
- `KEYRYX_WITNESS_DATA`
- `KEYRYX_WITNESS_ROOT_KEY_FILE`
- `KEYRYX_WITNESS_EVENTS`
- `KEYRYX_WITNESS_CHECKPOINTS`
- `KEYRYX_WITNESS_CUSTODY_URL`
- `KEYRYX_WITNESS_STREAM_KEYS`
- `KEYRYX_WITNESS_DELEGATION_ROOT_PIN`
- `KEYRYX_WITNESS_ALERTS`
- `KEYRYX_WITNESS_RECORDS`
- `KEYRYX_WITNESS_ADDR`
- `KEYRYX_WITNESS_INTERVAL`
- `KEYRYX_WITNESS_FULL_BYTES`
- `KEYRYX_WITNESS_FULL_INTERVAL`
- `KEYRYX_WITNESS_SEAL_EVERY`
- `KEYRYX_WITNESS_SEAL_LINES`
- `KEYRYX_WITNESS_NAME`
- `KEYRYX_WITNESS_TSA_URL`
- `KEYRYX_WITNESS_TSA_CA`
- `KEYRYX_WITNESS_TSA_EVERY`
- held in: `cmd/keyryx/main.go`, `cmd/keyryx/witness.go`, `internal/config/config.go`, `internal/wconfig/wconfig.go`

### http.custody.routes (10)

- `/healthz`
- `/v1/state`
- `/v1/keys`
- `/v1/jwks/{name}`
- `/v1/statements/{kid}`
- `/v1/keys/{name}/sign`
- `/v1/keys/{name}/challenge`
- `/v1/keys/{name}/delegate`
- `/v1/keys/{name}/rotate`
- `/v1/kids/{kid}/revoke`
- held in: `internal/api/api.go`

### http.witness.routes (6)

- `/healthz`
- `/v1/witness/head`
- `/v1/witness/keys`
- `/v1/witness/inclusion`
- `/v1/witness/consistency`
- `/v1/witness/entries`
- held in: `internal/witnessapi/witnessapi.go`

### statement.claims (11)

- `v`
- `iss`
- `name`
- `owner`
- `kid`
- `jwk`
- `not_before`
- `not_after`
- `issued_at`
- `jti`
- `roots`
- held in: `internal/statement/statement.go`

### witness.findings (7)

- `witness_stream_rewritten`
- `witness_stream_truncated`
- `witness_chain_restarted`
- `witness_checkpoint_invalid`
- `witness_checkpoint_unsigned`
- `witness_root_equivocated`
- `witness_root_missing`
- held in: `internal/witness/witness.go`, `cmd/keyryx/main.go`

## Additive within a major

- A new KEYRYX_ variable that is optional and changes nothing when unset
- A new witness finding with a new name, which a verifier reads as unknown until it is taught it
- A new route, listed here in the release that adds it

## Experimental

- The ML-DSA-65 key set form (AKP) follows a JOSE draft, not a published RFC
- The witness's RFC 3161 support, which is tested against authorities the tests build and has not been run against a public one

## Support

The newest minor gets every fix; the previous minor gets security-relevant fixes for 90 days after the newer one is tagged. Before this repository's 1.0, only `main` is supported.
