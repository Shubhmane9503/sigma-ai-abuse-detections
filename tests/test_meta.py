"""Repository conventions: every rule has samples, a filter and the required metadata."""

import re

import pytest
import yaml

from harness import DATA_DIR, FILTERS_DIR, SAMPLE_KINDS, load_events, rule_cases

CASES = rule_cases()
REQUIRED_RULE_FIELDS = (
    "title", "id", "status", "description", "references", "author",
    "date", "modified", "falsepositives", "level",
)  # fmt: skip
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def documents(path):
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]


def test_rules_exist():
    assert len(CASES) >= 8, "the MVP defines 8 rules"


@pytest.mark.parametrize("kind", SAMPLE_KINDS)
@pytest.mark.parametrize("case", CASES, ids=str)
def test_rule_has_non_empty_samples(case, kind):
    path = case.sample(kind)
    assert path.is_file(), f"missing sample file tests/data/{case.stem}/{kind}.ndjson"
    assert load_events(path), f"empty sample file tests/data/{case.stem}/{kind}.ndjson"


@pytest.mark.parametrize("case", CASES, ids=str)
def test_samples_record_their_origin(case):
    source = case.data_dir / "SOURCE.md"
    assert source.is_file(), f"tests/data/{case.stem}/SOURCE.md must say where each sample file came from"
    text = source.read_text(encoding="utf-8")
    for kind in SAMPLE_KINDS:
        assert f"{kind}.ndjson" in text, f"tests/data/{case.stem}/SOURCE.md does not describe {kind}.ndjson"


def test_no_orphan_sample_directories():
    stems = {case.stem for case in CASES}
    orphans = sorted(p.name for p in DATA_DIR.iterdir() if p.is_dir() and p.name not in stems)
    assert not orphans, f"sample directories without a rule: {orphans}"


@pytest.mark.parametrize("case", CASES, ids=str)
def test_rule_metadata(case):
    for doc in documents(case.path):
        missing = [name for name in REQUIRED_RULE_FIELDS if not doc.get(name)]
        assert not missing, f"{case.path.name} ({doc.get('title')}): missing {missing}"
        assert UUID.match(str(doc["id"])), f"{case.path.name}: id must be a random (v4) UUID"
        assert "logsource" in doc or "correlation" in doc
        assert "detection" in doc or "correlation" in doc
        assert doc["modified"] >= doc["date"]


def test_rule_ids_are_unique():
    ids = [doc["id"] for case in CASES for doc in documents(case.path)]
    ids += [doc["id"] for path in FILTERS_DIR.glob("*.yml") for doc in documents(path)]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, f"duplicate ids: {duplicates}"


@pytest.mark.parametrize("case", CASES, ids=str)
def test_rule_has_allowlist_filter_targeting_it(case):
    assert case.filter_path.is_file(), f"missing allowlist filter filters/{case.filter_path.name}"
    targets = set(documents(case.filter_path)[0]["filter"]["rules"])
    rule_ids = {doc["id"] for doc in documents(case.path)}
    assert targets & rule_ids, f"{case.filter_path.name} does not reference any rule in {case.path.name}"


def test_no_orphan_filters():
    stems = {case.stem for case in CASES}
    orphans = sorted(p.name for p in FILTERS_DIR.glob("*.yml") if p.stem.removesuffix("_allowlist") not in stems)
    assert not orphans, f"filters without a rule: {orphans}"


@pytest.mark.parametrize("case", CASES, ids=str)
def test_rule_description_names_its_filter(case):
    main = documents(case.path)[-1]
    assert case.filter_path.name in main["description"], "the description should point to the allowlist hook"
