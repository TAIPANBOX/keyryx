#!/usr/bin/env bash
# Each gate is shown its own fault and required to fail on it, then shown a
# non-fault and required not to (CLAUDE.md invariant 15). A gate that cannot go
# red is a green badge over nothing, and eight of them in this estate could
# not, once.
#
# Needs a clean tree: it edits tracked files and restores with `git checkout`,
# and cannot tell your edits from its own.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || {
  echo "this script mutates tracked files, so it needs a clean tree." >&2
  echo "commit first." >&2
  exit 2
}
cases=0

# fault: replace exactly one occurrence of an anchor in one file, run the
# gate, restore, and require the expected outcome. Exactly one, so an anchor
# that matches nothing or matches by accident aborts the case instead of
# reporting teeth it did not test.
fault() { # name file from to expect(fail|pass) gate [args]
  local name="$1" file="$2" from="$3" to="$4" expect="$5"
  shift 5
  python3 - "$file" "$from" "$to" <<'PY'
import io, sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = io.open(p, encoding="utf-8").read()
assert s.count(a) == 1, f"anchor x{s.count(a)} in {p}"
io.open(p, "w", encoding="utf-8").write(s.replace(a, b))
PY
  if "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
  git checkout -- . >/dev/null 2>&1
  cases=$((cases + 1))
  if [ "$got" != "$expect" ]; then
    echo "TOOTHLESS: $name -> $got, wanted $expect" >&2
    exit 1
  fi
  printf "ok  %-60s (%s)\n" "$name" "$expect"
}

# fault_all: every occurrence, at least one, for a fault whose honest shape is
# "every one of these is gone".
fault_all() { # name file from to expect gate [args]
  local name="$1" file="$2" from="$3" to="$4" expect="$5"
  shift 5
  python3 - "$file" "$from" "$to" <<'PY'
import io, sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = io.open(p, encoding="utf-8").read()
assert s.count(a) >= 1, f"anchor absent in {p}"
io.open(p, "w", encoding="utf-8").write(s.replace(a, b))
PY
  if "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
  git checkout -- . >/dev/null 2>&1
  cases=$((cases + 1))
  if [ "$got" != "$expect" ]; then
    echo "TOOTHLESS: $name -> $got, wanted $expect" >&2
    exit 1
  fi
  printf "ok  %-60s (%s)\n" "$name" "$expect"
}

# --- features-are-bound ---------------------------------------------------
fault "features: a scenario names a test that does not exist" \
  features/scaffold.feature '# @test:TestTheVersionIsPrintedAndExitsZero' '# @test:TestNoSuchTestAnywhere' \
  fail ./scripts/features-are-bound.sh
fault "features: a scenario loses its binding" \
  features/scaffold.feature '  # @test:TestTheVersionIsPrintedAndExitsZero' '  # (unbound)' \
  fail ./scripts/features-are-bound.sh
fault "features: a scenario's wording changes, binding kept" \
  features/scaffold.feature 'Scenario: The binary says which build it is' 'Scenario: The binary says which build it was built as' \
  pass ./scripts/features-are-bound.sh

# --- readme-numbers -------------------------------------------------------
fault "readme numbers: the badge drifts from the suite" \
  README.md 'tests-' 'tests-99999-' \
  fail ./scripts/readme-numbers.sh
# The anchor is read from README.md rather than pinned here: the number in it
# is exactly what this repository's own tests keep changing.
prose_anchor=$(grep -oE '^[0-9]+ tests\. Tier T3:' README.md | head -1 || true)
[ -n "$prose_anchor" ] || {
  echo "UNJUDGEABLE: readme numbers: no '<N> tests. Tier T3:' line in README.md; this case measured nothing" >&2
  exit 1
}
fault "readme numbers: the prose count drifts from the suite" \
  README.md "$prose_anchor" '999 tests. Tier T3:' \
  fail ./scripts/readme-numbers.sh

# --- base-images-pinned-by-digest -----------------------------------------
fault "base images: a FROM falls back to a moving tag" \
  Dockerfile 'golang@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c' 'golang:1.27' \
  fail ./scripts/base-images-pinned-by-digest.sh
fault_all "base images: every FROM line is gone" \
  Dockerfile 'FROM ' '# was FROM ' \
  fail ./scripts/base-images-pinned-by-digest.sh
fault "base images: an unrelated label changes" \
  Dockerfile 'org.opencontainers.image.title="keyryx"' 'org.opencontainers.image.title="keyryx" ' \
  pass ./scripts/base-images-pinned-by-digest.sh

# --- dependencies-are-argued ----------------------------------------------
fault "dependencies: a require line nobody argued" \
  go.mod 'toolchain go1.27.2' $'toolchain go1.27.2\n\nrequire example.com/unargued v1.0.0' \
  fail ./scripts/dependencies-are-argued.sh
fault "dependencies: a require block nobody argued" \
  go.mod 'toolchain go1.27.2' $'toolchain go1.27.2\n\nrequire (\n\texample.com/unargued v1.0.0 // indirect\n)' \
  fail ./scripts/dependencies-are-argued.sh
fault "dependencies: go.mod names no module" \
  go.mod 'module github.com/TAIPANBOX/keyryx' 'modul github.com/TAIPANBOX/keyryx' \
  fail ./scripts/dependencies-are-argued.sh
fault "dependencies: a comment in go.mod, nothing required" \
  go.mod 'toolchain go1.27.2' $'toolchain go1.27.2\n\n// a comment, no dependency' \
  pass ./scripts/dependencies-are-argued.sh

# --- no-owner-quotes ------------------------------------------------------
# The owner's first name is assembled, never written here, so this file is not
# itself a finding of the gate it tests.
owner_first="Y""urii"
owner_marker="@$(printf '%s' "$owner_first" | tr '[:upper:]' '[:lower:]')"
fault "owner quotes: the old provenance marker" \
  README.md '## Licence' "## Licence $owner_marker 2026-10-18" \
  fail ./scripts/no-owner-quotes.sh
fault "owner quotes: the owner named as the one who decided" \
  README.md '## Licence' "## Licence ($owner_first decided this)" \
  fail ./scripts/no-owner-quotes.sh
fault "owner quotes: Ukrainian prose in a doc" \
  README.md '## Licence' "## Licence $(printf '\xd0\xbb\xd1\x96\xd1\x86\xd0\xb5\xd0\xbd\xd0\xb7\xd1\x96\xd1\x8f')" \
  fail ./scripts/no-owner-quotes.sh
fault "owner quotes: the owner as copyright holder" \
  README.md '## Licence' "## Licence (copyright $owner_first)" \
  pass ./scripts/no-owner-quotes.sh

# --- no-long-dashes -------------------------------------------------------
long_dash="$(printf '\xe2\x80\x94')"
fault "long dashes: one in the README" \
  README.md '## Licence' "## Licence $long_dash" \
  fail ./scripts/no-long-dashes.sh
fault "long dashes: one in a Go comment" \
  cmd/keyryx/main.go '// version is overridden' "// version $long_dash is overridden" \
  fail ./scripts/no-long-dashes.sh
fault "long dashes: a short hyphen is not one" \
  README.md '## Licence' '## Licence - and a hyphen' \
  pass ./scripts/no-long-dashes.sh

# --- private-keys-stay-in-the-store --------------------------------------
fault "private keys: a handler grows a reference to a private key" \
  internal/api/api.go 'type ctxKey struct{}' $'type ctxKey struct{}\n\nvar _ *ecdsa.PrivateKey' \
  fail ./scripts/private-keys-stay-in-the-store.sh
fault_all "private keys: the store handles none, so nothing is measured" \
  internal/keystore/keystore.go 'Key' 'Kee' \
  fail ./scripts/private-keys-stay-in-the-store.sh
fault "private keys: a comment outside the store names one" \
  internal/api/api.go 'type ctxKey struct{}' 'type ctxKey struct{} // never an ecdsa.PrivateKey' \
  pass ./scripts/private-keys-stay-in-the-store.sh

# --- compat-surface ------------------------------------------------------
fault "compat: a frozen route leaves the code" \
  internal/api/api.go '{"GET", "/v1/state", "public"}' '{"GET", "/v1/states", "public"}' \
  fail ./scripts/compat-surface.sh
fault "compat: COMPATIBILITY.md drifts from the manifest" \
  COMPATIBILITY.md '## Frozen' '## Frozen (edited by hand)' \
  fail ./scripts/compat-surface.sh
fault "compat: the manifest freezes nothing" \
  compat/1.0.json '"frozen": {' '"frozen_removed": {' \
  fail ./scripts/compat-surface.sh
fault "compat: a comment on a route table changes, no name does" \
  internal/api/api.go '// Routes is the route table: every route this service serves, and only those.' '// Routes is the route table: every route this service serves, and only those (see the README).' \
  pass ./scripts/compat-surface.sh

# --- svg-text-fit --------------------------------------------------------
fault "svg text: a label outgrows its box" \
  docs/architecture.svg '>Publishes key sets with an overlap<' '>Publishes key sets with an overlap and keeps every retired key<' \
  fail ./scripts/svg-text-fit.sh
fault "svg text: a label leaves every box" \
  docs/delegation.svg 'y="277" font-family' 'y="2770" font-family' \
  fail ./scripts/svg-text-fit.sh
fault "svg text: a transform is not measured" \
  docs/delegation.svg '<text x="480" y="277"' '<text transform="translate(0 0)" x="480" y="277"' \
  fail ./scripts/svg-text-fit.sh
fault "svg text: a face with no measured widths" \
  docs/architecture.svg 'font-family="Helvetica, Arial, sans-serif" font-size="16" text-anchor="middle" fill="#1b1b1b">keyryx custody' 'font-family="Georgia" font-size="16" text-anchor="middle" fill="#1b1b1b">keyryx custody' \
  fail ./scripts/svg-text-fit.sh
fault "svg text: the root is not an SVG document" \
  docs/delegation.svg 'xmlns="http://www.w3.org/2000/svg"' 'xmlns="http://example.com/svg"' \
  fail ./scripts/svg-text-fit.sh
fault "svg text: a label that gets shorter keeps passing" \
  docs/architecture.svg '>approval tokens<' '>approvals<' \
  pass ./scripts/svg-text-fit.sh
if ./scripts/svg-text-fit.sh docs/no-diagrams-here >/dev/null 2>&1; then
  echo "TOOTHLESS: svg text: a path with no diagram -> pass, wanted fail" >&2
  exit 1
fi
cases=$((cases + 1))
printf "ok  %-60s (%s)\n" "svg text: a path with no diagram measures nothing" "fail"

# --- every gate in scripts/ has a case here --------------------------------
uncovered=""
for gate in scripts/*.sh; do
  base="$(basename "$gate")"
  [ "$base" = gates-have-teeth.sh ] && continue
  grep -qF -- "./scripts/$base" "$0" || uncovered="$uncovered $base"
done
if [ -n "$uncovered" ]; then
  echo
  echo "no case in this file exercises:$uncovered" >&2
  echo "A gate with no case here is a gate nothing proves can go red." >&2
  exit 1
fi

echo
echo "$cases cases: every gate fails on its own fault and passes on what it must not catch."
