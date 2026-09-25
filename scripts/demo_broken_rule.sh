#!/usr/bin/env bash
# Demo: break a rule the way a careless edit would and show the test suite catching it.
#
# Copies the repository to a temporary directory, renames the field in the Bedrock
# model-access rule (eventSource -> eventSrc), and runs the replay tests there.
# The working tree is never modified. Exits 0 when the tests fail as expected.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"
git ls-files -z --cached --others --exclude-standard | xargs -0 -I{} cp --parents {} "$WORK"
RULE=rules/cloud/aws/aws_bedrock_model_access_enabled.yml
sed -i 's/^        eventSource: bedrock.amazonaws.com/        eventSrc: bedrock.amazonaws.com/' "$WORK/$RULE"

echo "Broken rule (diff):"
diff -u "$RULE" "$WORK/$RULE" || true
echo
echo "Running the replay tests against the broken rule..."
cd "$WORK"
if JSON_MATCHER="${ROOT}/.venv/bin/json_matcher" "$PY" -m pytest -q -p no:cacheprovider tests/test_replay.py -k aws_bedrock_model_access_enabled; then
    echo "UNEXPECTED: the tests passed on a broken rule" >&2
    exit 1
fi
echo
echo "As expected, the tests failed: a pull request with this change would be blocked."
