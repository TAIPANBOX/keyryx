#!/usr/bin/env bash
# Every module go.mod requires is argued in DEPENDENCIES.md (CLAUDE.md
# invariant 8).
#
# WHY
#
# This service holds signing keys. The standard library is the first choice
# for everything it does (crypto/ecdsa, crypto/mldsa, crypto/aes, crypto/hkdf,
# net/http), and a third-party module is a decision argued in the pull request
# that adds it, then written down with its reason where the next reader finds
# it. A require line with no entry there is a dependency nobody decided on.
#
# HOW
#
# Every module path in go.mod's require directives, direct or indirect, must
# appear in DEPENDENCIES.md on a line of its own table, `| <module path> | ...`,
# with a non-empty reason. A missing go.mod is "measured nothing", never OK.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f go.mod ] || { echo "FAIL: no go.mod; this gate measured nothing" >&2; exit 1; }
[ -f DEPENDENCIES.md ] || { echo "FAIL: no DEPENDENCIES.md to argue dependencies in" >&2; exit 1; }

python3 - <<'PY'
import re, sys

mod = open("go.mod", encoding="utf-8").read()
if not re.search(r"^module\s+\S+", mod, re.M):
    print("FAIL: go.mod names no module; this gate measured nothing")
    sys.exit(1)

required = []
in_block = False
for raw in mod.splitlines():
    line = raw.split("//", 1)[0].strip()
    if not line:
        continue
    if in_block:
        if line == ")":
            in_block = False
            continue
        required.append(line.split()[0])
        continue
    if re.match(r"^require\s*\($", line):
        in_block = True
        continue
    m = re.match(r"^require\s+(\S+)\s+\S+", line)
    if m:
        required.append(m.group(1))

argued = {}
for raw in open("DEPENDENCIES.md", encoding="utf-8").read().splitlines():
    m = re.match(r"^\|\s*`?([^|`\s]+)`?\s*\|\s*([^|]*?)\s*\|", raw)
    if m and "/" in m.group(1):
        argued[m.group(1)] = m.group(2)

bad = [r for r in required if not argued.get(r, "").strip()]
for r in bad:
    print(f"FAIL: go.mod requires {r} and DEPENDENCIES.md does not argue it")
if bad:
    sys.exit(1)
print(f"dependencies: {len(required)} required module(s), every one argued")
PY
