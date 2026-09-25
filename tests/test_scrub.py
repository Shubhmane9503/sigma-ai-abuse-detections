"""Samples must contain placeholders only: no real account IDs, keys, IPs or emails."""

from scrub_samples import check_files, check_text, sample_files, scrub_text

# Key-shaped test values are assembled at runtime so secret scanners do not flag this file.
FAKE_AKIA = "AKIA" + "6FTSFH98XNF7DFZB"
FAKE_ASIA = "ASIA" + "6FTSFH98XNF7DFZB"


def test_samples_are_scrubbed():
    findings = check_files(sample_files())
    assert not findings, "values that look real in samples:\n" + "\n".join(map(str, findings))


def test_checker_flags_real_looking_values():
    text = (
        '{"accountId": "494659789341", "key": "' + FAKE_AKIA + '", "ip": "35.249.253.232",'
        ' "caller": "alice@contoso.com", "sub": "/subscriptions/3f2a1b4c-1111-2222-3333-444455556666/rg"}'
    )
    kinds = {finding.kind for finding in check_text(text)}
    assert kinds == {"AWS account ID", "AWS key or principal ID", "public IP address", "email address", "Azure subscription/tenant ID"}


def test_checker_accepts_placeholders():
    text = (
        '{"accountId": "111122223333", "key": "AKIAIOSFODNN7EXAMPLE", "ip": "203.0.113.10", "lan": "10.1.2.3",'
        ' "caller": "user@example.com", "sub": "/subscriptions/00000000-0000-0000-0000-000000000000/rg"}'
    )
    assert check_text(text) == []


def test_scrub_text_is_consistent():
    text = '{"a": "494659789341", "ip": "35.1.2.3", "ip2": "35.1.2.3", "k": "' + FAKE_ASIA + '"}'
    scrubbed = scrub_text(text)
    assert check_text(scrubbed) == []
    assert scrubbed.count(scrub_text("35.1.2.3")) == 2
