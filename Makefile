# All targets run the same way locally and in CI. Start with `make setup`.

PYTHON      ?= python3
VENV        ?= .venv
BIN         := $(VENV)/bin
PY          := $(BIN)/python

# SigmaHQ json_matcher v0.0.2, pinned by commit. Built from source because its go.mod
# declares the module path "sigma_regression", which breaks `go install`.
JSON_MATCHER_REPO   := https://github.com/SigmaHQ/json_matcher
JSON_MATCHER_COMMIT := 3bb3022bbe093cab0edf81d48ee4559548645d72
JSON_MATCHER        := $(BIN)/json_matcher

.PHONY: help setup lint check test test-esql convert snapshots mappings matrix scrub framework-data framework-check demo clean

help:
	@echo "make setup            create $(VENV), install pinned tools, build json_matcher"
	@echo "make lint             yamllint over rules, filters, pipelines and workflows"
	@echo "make check            sigma check over rules/ and filters/ (issues fail the build)"
	@echo "make test             sigma check + full pytest suite"
	@echo "make test-esql        run committed ES|QL queries on Elasticsearch (needs ESQL_TEST_URL)"
	@echo "make convert          regenerate queries/ (Splunk SPL, Elastic ES|QL)"
	@echo "make snapshots        regenerate queries/ and tests/snapshots/ after an intentional change"
	@echo "make mappings         validate ATT&CK / ATLAS IDs against pinned data"
	@echo "make matrix           regenerate docs/coverage.md"
	@echo "make scrub            check samples for real-looking identifiers"
	@echo "make framework-check  re-download pinned ATT&CK/ATLAS and verify the committed extracts"
	@echo "make demo             show the tests failing on a deliberately broken rule"

$(PY):
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip

setup: $(PY) $(JSON_MATCHER)
	$(BIN)/pip install --quiet -r requirements.txt

$(JSON_MATCHER): | $(PY)
	rm -rf build/json_matcher
	git clone --quiet $(JSON_MATCHER_REPO) build/json_matcher
	git -C build/json_matcher checkout --quiet $(JSON_MATCHER_COMMIT)
	cd build/json_matcher && GOTOOLCHAIN=auto go build -o $(abspath $(JSON_MATCHER)) .

lint:
	$(BIN)/yamllint --strict rules filters pipelines .github .yamllint

check:
	$(PY) scripts/sigma_check.py --fail-on-issues rules/ filters/

test: lint check
	$(PY) -m pytest

# Needs an Elasticsearch 9.x node, e.g.
#   docker run -d -p 9200:9200 -e discovery.type=single-node -e xpack.security.enabled=false elasticsearch:9.1.5
test-esql:
	@test -n "$(ESQL_TEST_URL)" || (echo "set ESQL_TEST_URL, e.g. ESQL_TEST_URL=http://localhost:9200" && exit 1)
	ESQL_TEST_URL=$(ESQL_TEST_URL) $(PY) -m pytest tests/test_esql_execution.py

convert:
	$(PY) scripts/conversions.py --queries-only

snapshots:
	$(PY) scripts/conversions.py

mappings:
	$(PY) scripts/validate_mappings.py

matrix:
	$(PY) scripts/coverage_matrix.py

scrub:
	$(PY) scripts/scrub_samples.py

framework-data:
	$(PY) scripts/fetch_framework_data.py

framework-check:
	$(PY) scripts/fetch_framework_data.py --check

demo:
	./scripts/demo_broken_rule.sh

clean:
	rm -rf build .cache .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
