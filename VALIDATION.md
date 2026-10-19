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
- @measured `gh run list -R TAIPANBOX/keyryx` 2026-10-19: the ci, secretscan and Scorecard workflows succeeded on `9bf76ec`, the head of main when this was checked.

## Not run here

- The cosign signature of v0.1.1 was not verified. cosign is not installed on the machine that made these measurements, and the keyless command in SECURITY.md has not been run.
- No container was started from the published image.
- The diagrams were not rendered in a browser. The text-fit gate measures against Helvetica's advance widths.
- The release workflow has not run on this branch. CI on the pull request is its first run.
