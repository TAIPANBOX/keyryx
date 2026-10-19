# Contributing to keyryx

keyryx holds signing keys and the witness of an agent-governance record, so a
change is held to a higher bar than most. This file says what that bar is and
where each part of it is checked.

## Development

Go 1.27 or later (the toolchain is pinned in `go.mod`). From a clean checkout:

```bash
go build ./...
go vet ./...
staticcheck ./...
test -z "$(gofmt -l .)"
go test ./... -race
make gates
```

`make gates` runs the repository's gate scripts. `scripts/gates-have-teeth.sh`
needs a clean tree, because it plants a fault in each gate's subject, requires
the gate to fail on it, and restores the file with `git checkout`. Run it after
committing.

The working instructions, the numbered invariants and the tier of each kind of
change are in [CLAUDE.md](./CLAUDE.md). Read the invariants that touch your
change before you start.

## Conventions

- **Scenarios first.** Behaviour is written as Given, When, Then in
  `features/*.feature` before the code. Each scenario is bound to a test with a
  `# @test:<TestName>` line, and `scripts/features-are-bound.sh` checks the
  binding in both directions.
- **Red first.** A new test fails against the code as it was before the change.
  Put that failing output in the pull request.
- **Tiers.** A change to a key, a signature, a statement format, the store,
  consumer authentication or the witness log is tier T3. For those, name in the
  pull request each mutant you broke on purpose and the test that caught it.
- **Dependencies.** The standard library comes first. A third-party module is
  argued in the pull request that adds it and recorded in `DEPENDENCIES.md`.
- **Public text.** No long dashes in any tracked file. Decisions are recorded
  as `@decided YYYY-MM-DD` with a paraphrase, not a quotation of a person.
- **Commits.** Conventional Commits, one logical change per commit.

## Pull requests

- Describe what changed and why. Paste the red output and the gate output.
- If the change alters a frozen name in `compat/1.0.json`, say so and name the
  major version it belongs to. A frozen name that leaves the code fails
  `scripts/compat-surface.sh`.
- If the change alters a number the README states (tests, scenarios), run
  `scripts/readme-numbers.sh` and update the README in the same pull request.

## Security

Do not report a vulnerability in a public issue or a public pull request. Use
the private advisory route in [SECURITY.md](./SECURITY.md).
