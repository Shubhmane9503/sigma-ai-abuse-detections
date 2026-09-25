#!/usr/bin/env python3
"""Check (and help scrub) sample logs for values that look real.

Samples may only contain placeholder identifiers. This check fails on:
  - 12-digit AWS account IDs other than the AWS documentation placeholders
  - AWS access key IDs that are not documentation examples (must contain "EXAMPLE")
  - IPv4 addresses outside private, loopback and RFC 5737 documentation ranges
  - Azure subscription / tenant GUIDs that are not all-zero placeholders
  - email addresses outside reserved example domains (RFC 2606) and the .internal TLD
  - private keys and common API token formats

Usage:
  python scripts/scrub_samples.py            # check tests/data, exit 1 on findings
  python scripts/scrub_samples.py FILE...    # check specific files
  python scripts/scrub_samples.py --apply FILE...
      rewrite files, replacing account IDs, access keys and public IPs with placeholders
      (review the diff afterwards; identity names and hostnames still need a manual pass)
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "tests" / "data"

ALLOWED_ACCOUNT_IDS = {"111122223333", "444455556666", "123456789012"}
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")
ALLOWED_EMAIL_TLDS = (".example", ".invalid", ".test", ".localhost", ".internal")
PLACEHOLDER_GUID = re.compile(r"^00000000-0000-0000-0000-[0-9a-f]{12}$", re.IGNORECASE)

ACCOUNT_ID = re.compile(r"(?<![\w.-])\d{12}(?![\w-])")
ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|AIPA)[A-Z0-9]{12,20}\b")
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
AZURE_SCOPED_GUID = re.compile(
    r"(?:subscriptions/|\"(?:SubscriptionId|TenantId|subscriptionId|tenantId)\":\s*\")"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
SECRETS = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Anthropic API key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI API key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"),
    "AWS secret key assignment": re.compile(r"aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
}


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    kind: str
    value: str

    def __str__(self) -> str:
        try:
            shown = self.path.relative_to(ROOT)
        except ValueError:
            shown = self.path
        return f"{shown}:{self.line}: {self.kind}: {self.value}"


def _ip_allowed(text: str) -> bool:
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return False  # leading zeros or out-of-range octets: treat as suspicious
    return address.is_private or address.is_loopback or address.is_unspecified


def check_text(text: str, path: Path = Path("<text>")) -> list[Finding]:
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        for match in ACCOUNT_ID.finditer(line):
            if match.group(0) not in ALLOWED_ACCOUNT_IDS:
                findings.append(Finding(path, number, "AWS account ID", match.group(0)))
        for match in ACCESS_KEY.finditer(line):
            if "EXAMPLE" not in match.group(0):
                findings.append(Finding(path, number, "AWS key or principal ID", match.group(0)))
        for match in IPV4.finditer(line):
            if not _ip_allowed(match.group(1)):
                findings.append(Finding(path, number, "public IP address", match.group(1)))
        for match in AZURE_SCOPED_GUID.finditer(line):
            if not PLACEHOLDER_GUID.match(match.group(1)):
                findings.append(Finding(path, number, "Azure subscription/tenant ID", match.group(1)))
        for match in EMAIL.finditer(line):
            domain = match.group(1).lower()
            if not (domain in ALLOWED_EMAIL_DOMAINS or domain.endswith(ALLOWED_EMAIL_TLDS)):
                findings.append(Finding(path, number, "email address", match.group(0)))
        for kind, pattern in SECRETS.items():
            for match in pattern.finditer(line):
                findings.append(Finding(path, number, kind, match.group(0)[:24] + "..."))
    return findings


def sample_files() -> list[Path]:
    return sorted(p for p in DATA_DIR.rglob("*") if p.is_file() and p.suffix in {".ndjson", ".json", ".log"})


def check_files(paths: list[Path]) -> list[Finding]:
    findings = []
    for path in paths:
        findings.extend(check_text(path.read_text(encoding="utf-8"), path))
    return findings


def _placeholder_ip(value: str) -> str:
    digest = int(hashlib.sha256(value.encode()).hexdigest(), 16)
    return f"203.0.113.{digest % 254 + 1}"


def scrub_text(text: str) -> str:
    """Replace the mechanical cases consistently: same input value, same placeholder."""
    text = ACCOUNT_ID.sub(lambda m: m.group(0) if m.group(0) in ALLOWED_ACCOUNT_IDS else "111122223333", text)
    text = ACCESS_KEY.sub(lambda m: m.group(0) if "EXAMPLE" in m.group(0) else m.group(0)[:4] + "IOSFODNN7EXAMPLE", text)
    text = IPV4.sub(lambda m: m.group(1) if _ip_allowed(m.group(1)) else _placeholder_ip(m.group(1)), text)
    return text


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--apply":
        for name in argv[1:]:
            path = Path(name)
            path.write_text(scrub_text(path.read_text(encoding="utf-8")), encoding="utf-8")
            print(f"scrubbed {path}")
        argv = argv[1:]
    paths = [Path(p) for p in argv] if argv else sample_files()
    findings = check_files(paths)
    for finding in findings:
        print(finding)
    if findings:
        print(f"{len(findings)} finding(s): replace them with placeholders (see scripts/scrub_samples.py)")
        return 1
    print(f"scrub check passed ({len(paths)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
