# Validation

What this repository has been checked against, and how to check it again.

Each measured result carries the command that produced it and the date, as
`@measured <command> <date>`, so a reader can run the same command. A claim
without that marker has not been run: check it before relying on it. What was
not run is listed at the end, and the same limits are in the README under
NOT PROVEN.

## Gates and tests on this change

- @measured `./scripts/compat-surface.sh` 2026-10-19: OK, 65 frozen names across 6 kinds are present in the code, and COMPATIBILITY.md is their rendering.
- @measured `./scripts/svg-text-fit.sh` 2026-10-19: OK, 39 texts in 2 diagrams fit their boxes; the smallest slack is 10.6px, against a minimum of 6px.
- @measured `go test ./cmd/keyryx/ -run 'TestTheReadmeStatesWhatIsPublished|TestTheReadmeHasTheHouseSections|TestEveryImageInTheReadmeHasAltText|TestTheHouseDocumentsExist|TestTheFrozenRoutesAreTheRouteTables' -v` 2026-10-19: all five pass.

## The published releases

- @measured `gh release list -R TAIPANBOX/keyryx` 2026-10-19: v0.1.1 is the latest release (published 2026-10-19T03:41:16Z), and v0.1.0 was published 2026-10-18T19:17:05Z.
- @measured anonymous pull token from `https://ghcr.io/token?scope=repository:taipanbox/keyryx:pull`, then `GET /v2/taipanbox/keyryx/tags/list`, 2026-10-19: the tags are v0.1.0, v0.1.1, `sha-e87afc6`, `sha-7384897` and the digest tags. The digest of v0.1.1 has a cosign signature tag (`sha256-a9f88c44...sig`). The digest of v0.1.0 has none.
- @measured `gh attestation verify oci://ghcr.io/taipanbox/keyryx:v0.1.0 -R TAIPANBOX/keyryx` 2026-10-19: exit 0.
- @measured `gh attestation verify oci://ghcr.io/taipanbox/keyryx:v0.1.1 -R TAIPANBOX/keyryx` 2026-10-19: exit 0.
- @measured `gh release list -R TAIPANBOX/keyryx` 2026-10-19: v0.1.2 is the latest release (published 2026-10-19T21:40:48Z); v0.1.1 and v0.1.0 are listed unchanged.
- @measured anonymous pull token from `https://ghcr.io/token?scope=repository:taipanbox/keyryx:pull`, then `GET /v2/taipanbox/keyryx/tags/list`, 2026-10-19: the tags include v0.1.2 and `sha-21edb5c`. `GET /v2/taipanbox/keyryx/manifests/v0.1.2` answers HTTP 200 with `docker-content-digest` `sha256:9b6d4e0e8988076e90843d9d1625e50a7f248f6be531e144a6950ff9233f7683`, and the digest has a cosign signature tag (`sha256-9b6d4e0e...sig`). The signature itself was not verified (see Not run here).
- @measured `gh attestation verify oci://ghcr.io/taipanbox/keyryx:v0.1.2 -R TAIPANBOX/keyryx` 2026-10-19: exit 0.
- @measured `gh run list -R TAIPANBOX/keyryx` 2026-10-19: the release workflow for tag v0.1.2 (run 39329101525) succeeded.
- @measured `gh release list -R TAIPANBOX/keyryx` 2026-10-26: v0.1.3 is the latest release (published 2026-10-26T00:06:22Z) with `provenance.intoto.jsonl`, `sbom.cyclonedx.json` and `sbom.spdx.json`; v0.1.2, v0.1.1 and v0.1.0 are listed unchanged.
- @measured anonymous pull token from `https://ghcr.io/token?scope=repository:taipanbox/keyryx:pull`, then `GET /v2/taipanbox/keyryx/tags/list`, 2026-10-26: the tags include v0.1.3 and `sha-11df9c2`. `GET /v2/taipanbox/keyryx/manifests/v0.1.3` answers HTTP 200 with `docker-content-digest` `sha256:26d5d49cd4a67eb463f35895de96e628e2304183775bf031170e190c579c0147`, and the digest has a cosign signature tag (`sha256-26d5d49c...sig`). The signature itself was not verified (see Not run here).
- @measured `gh attestation verify oci://ghcr.io/taipanbox/keyryx:v0.1.3 -R TAIPANBOX/keyryx` 2026-10-26: exit 0.
- @measured `docker buildx imagetools inspect ghcr.io/taipanbox/keyryx:v0.1.3` 2026-10-26: an OCI index for linux/amd64 (`sha256:e4060fd1...`) and linux/arm64 (`sha256:9a34aec2...`) plus an attestation manifest.
- @measured the `/usr/local/bin/keyryx` file pulled from each platform layer of `ghcr.io/taipanbox/keyryx:v0.1.3`, then `go version <file>`, 2026-10-26: go1.27.3 for linux/amd64 and for linux/arm64. The same check on v0.1.2 printed go1.27.2.
- @measured `gh run list -R TAIPANBOX/keyryx` 2026-10-26: the release workflow for tag v0.1.3 (run 40247538465) succeeded.
- @measured `gh run list -R TAIPANBOX/keyryx` 2026-10-19: the ci, secretscan and Scorecard workflows succeeded on `9bf76ec`, the head of main when this was checked.

## Not run here

- The cosign signatures of v0.1.1, v0.1.2 and v0.1.3 were not verified. cosign is not installed on the machine that made these measurements, and the keyless command in SECURITY.md has not been run.
- No container was started from the published image.
- The diagrams were not rendered in a browser. The text-fit gate measures against Helvetica's advance widths.
- The release workflow ran on the tag v0.1.3 (run 40247538465, success) and earlier on v0.1.2 (run 39329101525, success). The pull request that carried the v0.1.3 notes did not run it.
