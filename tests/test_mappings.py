"""ATT&CK and ATLAS IDs are validated against pinned ATT&CK v19.2 and ATLAS 2026.09 data."""

import json

import pytest

from validate_mappings import ATLAS_EXTRACT, ATTACK_EXTRACT, rule_documents, validate

DOCUMENTS = rule_documents()


@pytest.mark.parametrize("path,doc", DOCUMENTS, ids=[doc["title"] for _, doc in DOCUMENTS])
def test_rule_mappings_are_valid(path, doc):
    result = validate(path, doc)
    assert not result.errors, f"{path.name} ({doc['title']}): " + "; ".join(result.errors)


def test_pinned_versions():
    attack = json.loads(ATTACK_EXTRACT.read_text(encoding="utf-8"))
    atlas = json.loads(ATLAS_EXTRACT.read_text(encoding="utf-8"))
    assert attack["x_extract_of"]["version"] == "19.2"
    assert atlas["x_extract_of"]["version"] == "2026.09"


def test_validator_rejects_unknown_and_revoked_ids(tmp_path):
    doc = {
        "title": "bad",
        "description": "",
        "tags": ["attack.t9999", "attack.t1562.008", "attack.not-a-tactic"],
        "atlas": ["AML.T9999"],
    }
    errors = " ".join(validate(tmp_path / "bad.yml", doc).errors)
    assert "T9999 is not in ATT&CK" in errors
    assert "T1562.008" in errors and "revoked" in errors
    assert "attack.not-a-tactic" in errors
    assert "AML.T9999 is not in ATLAS" in errors


def test_validator_requires_atlas(tmp_path):
    errors = validate(tmp_path / "x.yml", {"title": "x", "tags": ["attack.impact", "attack.t1496.004"]}).errors
    assert any("atlas" in error for error in errors)
