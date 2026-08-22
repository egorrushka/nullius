#!/usr/bin/env bash
# Everything CI does, run locally, in the same order and with the same
# exit behaviour.
#
#     bash tools/ci_local.sh
#
# Worth having separately from the workflow file because a red build on
# GitHub tells you something broke and then makes you wait five minutes
# per guess. This takes under a minute and fails in the same place.
#
# It deliberately does not reuse anything the workflow computed. Each step
# starts from the repository as checked out, which is the only way the
# byte-for-byte comparison means anything.

set -u
cd "$(dirname "$0")/.."

pass=0
fail=0
step() {
    printf '\n=== %s\n' "$1"
}
ok() {
    printf 'ok    %s\n' "$1"
    pass=$((pass + 1))
}
bad() {
    printf 'FAIL  %s\n' "$1"
    fail=$((fail + 1))
}

VERIFIER=verifier/target/release/ccert-verify
[ -f "$VERIFIER.exe" ] && VERIFIER="$VERIFIER.exe"

# 1 -----------------------------------------------------------------
step "the verifier builds without warnings"
if (cd verifier && RUSTFLAGS="-D warnings" cargo build --release >/tmp/ci_build.log 2>&1); then
    ok "cargo build --release, warnings denied"
else
    bad "cargo build"
    tail -20 /tmp/ci_build.log
fi

# 2 -----------------------------------------------------------------
step "the test suite"
if python3 -m pytest tests -q >/tmp/ci_tests.log 2>&1; then
    ok "$(tail -1 /tmp/ci_tests.log)"
else
    bad "pytest"
    tail -25 /tmp/ci_tests.log
fi

# 3 -----------------------------------------------------------------
step "every published certificate verifies from the file alone"
for cert in spec/vectors/valid/*.ccert; do
    name=$(basename "$cert" .ccert)
    if out=$("$VERIFIER" --require-proved "$cert" 2>&1); then
        ok "$name: $(echo "$out" | tail -1)"
    else
        bad "$name does not verify"
        echo "$out" | tail -5
    fi
done

# 4 -----------------------------------------------------------------
# The one worth having. If a certificate does not reproduce, it cannot be
# addressed by its hash, and the format loses the property it is built on.
step "rebuilding reproduces every certificate byte for byte"
rm -rf /tmp/ci_rebuilt && mkdir -p /tmp/ci_rebuilt
for name in $(python3 -m tools.build_curve --list); do
    vector="spec/vectors/valid/$name.ccert"
    if [ ! -f "$vector" ]; then
        bad "$name has no published vector to compare against"
        continue
    fi
    if ! python3 -m tools.build_curve --curve "$name" --out /tmp/ci_rebuilt --quiet \
            >/tmp/ci_rebuild.log 2>&1; then
        bad "$name failed to build"
        tail -5 /tmp/ci_rebuild.log
        continue
    fi
    if cmp -s "$vector" "/tmp/ci_rebuilt/$name.ccert"; then
        ok "$name reproduces exactly"
    else
        bad "$name does not reproduce"
        ls -l "$vector" "/tmp/ci_rebuilt/$name.ccert"
    fi
done

# 4b ----------------------------------------------------------------
step "every invalid vector is refused, for its own reason"
if out=$(python3 -m tools.make_invalid_vectors --check 2>&1); then
    ok "$(echo "$out" | tail -1)"
else
    bad "invalid vectors"
    echo "$out" | grep -E "ACCEPTED|WRONG" | head -8
fi

# 5 -----------------------------------------------------------------
# Not a gate on the verdicts. A curve failing a policy is a fact about the
# curve; what is checked here is that every policy still loads and
# evaluates, which catches a criterion naming a claim that no longer
# exists.
step "every policy loads and evaluates"
if python3 -m core.policy.engine --corpus spec/vectors/valid >/tmp/ci_policy.log 2>&1; then
    ok "policy matrix produced"
    sed -n '1,8p' /tmp/ci_policy.log
else
    bad "the policy engine raised"
    tail -10 /tmp/ci_policy.log
fi

# 6 -----------------------------------------------------------------
step "the web export runs"
rm -rf /tmp/ci_web
if python3 tools/export_web.py --corpus spec/vectors/valid --out /tmp/ci_web \
        >/tmp/ci_export.log 2>&1; then
    ok "$(tail -1 /tmp/ci_export.log)"
else
    bad "export_web.py"
    tail -10 /tmp/ci_export.log
fi

# 7 -----------------------------------------------------------------
# Skipped unless the dependencies are already installed: fetching them
# takes longer than everything above put together, and CI does it anyway.
step "the single-file page builds and stands alone"
if [ -d web/node_modules ]; then
    if (cd web && npm run build >/tmp/ci_web_build.log 2>&1); then
        if grep -qE 'src="(http|\./assets|/assets)' web/dist/index.html; then
            bad "the built page loads something from outside itself"
        else
            ok "page is self-contained, $(stat -c%s web/dist/index.html) bytes"
        fi
    else
        bad "vite build"
        tail -15 /tmp/ci_web_build.log
    fi
else
    printf 'skip  web build (run: cd web && npm ci)\n'
fi

# -------------------------------------------------------------------
printf '\n%s\n' "-------------------------------------------"
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
