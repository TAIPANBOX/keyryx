#!/usr/bin/env bash
# A private key is handled in one package and nowhere else (CLAUDE.md
# invariant 5).
#
# WHAT THIS CATCHES
#
# The custody surface answers key sets, inventories and signatures, and a
# private key reaching any of them would be the one failure this service exists
# to prevent. The behaviour is held by TestNoRouteAnswersWithAPrivateMember;
# this holds the SHAPE: every non-test Go file that names a private-key type or
# encodes or decodes one lives in internal/keystore. A handler, a log line or a
# config helper that grew a reference to a private key is a finding before any
# test runs. Finding no such reference in internal/keystore at all is "measured
# nothing", never OK: the store would then hold no private key, which means
# the patterns below no longer describe it.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import pathlib, re, sys

PATTERNS = re.compile(
    r"ecdsa\.PrivateKey|mldsa\.PrivateKey|ecdh\.PrivateKey|ed25519\.PrivateKey|rsa\.PrivateKey|"
    r"MarshalPKCS8PrivateKey|ParsePKCS8PrivateKey|MarshalECPrivateKey|ParseECPrivateKey|"
    r"mldsa\.NewPrivateKey|ecdsa\.GenerateKey|mldsa\.GenerateKey"
)
inside, outside = 0, []
for p in sorted(pathlib.Path(".").rglob("*.go")):
    if p.name.endswith("_test.go") or ".git" in p.parts:
        continue
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        code = line.split("//", 1)[0]
        if not PATTERNS.search(code):
            continue
        if p.parts[:2] == ("internal", "keystore"):
            inside += 1
        else:
            outside.append(f"{p}:{i}: {line.strip()[:100]}")
if inside == 0:
    print("no private-key handling was found in internal/keystore, so this gate measured nothing.")
    sys.exit(1)
for o in outside:
    print("FAIL: a private key is handled outside internal/keystore: " + o)
if outside:
    sys.exit(1)
print(f"private keys: {inside} reference(s), every one inside internal/keystore")
PY
