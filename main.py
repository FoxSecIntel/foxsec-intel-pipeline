#!/usr/bin/env python3
"""foxsec-intel-pipeline MVP

Domain enrichment and scoring for analyst triage.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from urllib.request import Request, urlopen


@dataclass
class DomainResult:
    domain: str
    ips: list[str]
    dmarc: str
    spf: str
    asn: str | None
    provider: str | None
    risk_score: int
    risk_level: str


def run(cmd: list[str], timeout: int = 6) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def resolve_ips(domain: str) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return sorted(set(ips))
    except socket.gaierror:
        return []


def dig_txt(name: str) -> list[str]:
    rc, out, _ = run(["dig", "+time=2", "+tries=1", "+short", "TXT", name])
    if rc != 0 or not out:
        return []
    return [line.strip().replace('"', "") for line in out.splitlines() if line.strip()]


def dmarc_status(domain: str) -> str:
    records = [t for t in dig_txt(f"_dmarc.{domain}") if "v=dmarc1" in t.lower()]
    if not records:
        return "missing"
    rec = records[0]
    match = re.search(r"\bp=([a-zA-Z]+)", rec, flags=re.I)
    if not match:
        return "invalid"
    policy = match.group(1).lower()
    if policy in ("none", "quarantine", "reject"):
        return "present"
    return "invalid"


def spf_status(domain: str) -> str:
    records = [t for t in dig_txt(domain) if "v=spf1" in t.lower()]
    if not records:
        return "missing"

    rec = records[0].lower()
    if "-all" in rec:
        return "strict"
    if "~all" in rec:
        return "softfail"
    if "?all" in rec:
        return "neutral"
    return "incomplete"


def asn_enrichment(ip: str) -> tuple[str | None, str | None]:
    url = f"https://api.bgpview.io/ip/{ip}"
    req = Request(url, headers={"User-Agent": "foxsec-intel-pipeline/0.1"})
    try:
        with urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8", errors="ignore"))
        data_obj = data.get("data") or {}
        prefixes = data_obj.get("prefixes") or []
        if prefixes:
            asn_obj = prefixes[0].get("asn") or {}
            asn_number = asn_obj.get("asn")
            provider = asn_obj.get("description")
            if asn_number is not None:
                return f"AS{asn_number}", provider
    except Exception:
        pass

    # Fallback: Team Cymru DNS ASN mapping
    try:
        octets = ip.split(".")
        if len(octets) == 4:
            qname = ".".join(reversed(octets)) + ".origin.asn.cymru.com"
            txt = dig_txt(qname)
            if txt:
                # format example: "13335 | 104.18.0.0/15 | US | arin | 2014-03-28"
                parts = [p.strip() for p in txt[0].split("|")]
                if parts and parts[0].isdigit():
                    return f"AS{parts[0]}", "Unknown"
    except Exception:
        pass

    return None, None


def calculate_risk(dmarc: str, spf: str, asn: str | None) -> tuple[int, str]:
    score = 0

    if dmarc == "missing":
        score += 30
    elif dmarc == "invalid":
        score += 20

    if spf == "missing":
        score += 30
    elif spf == "neutral":
        score += 20
    elif spf == "softfail":
        score += 12
    elif spf == "incomplete":
        score += 10

    if asn is None:
        score += 15

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return score, level


def run_domain_pipeline(domain: str) -> DomainResult:
    ips = resolve_ips(domain)
    dmarc = dmarc_status(domain)
    spf = spf_status(domain)

    asn = None
    provider = None
    if ips:
        asn, provider = asn_enrichment(ips[0])

    score, level = calculate_risk(dmarc, spf, asn)

    return DomainResult(
        domain=domain,
        ips=ips,
        dmarc=dmarc,
        spf=spf,
        asn=asn,
        provider=provider,
        risk_score=score,
        risk_level=level,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Domain enrichment and scoring pipeline")
    parser.add_argument("--domain", required=True, help="Domain to enrich and score")
    parser.add_argument("--output", choices=["json"], default="json", help="Output format")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run_domain_pipeline(args.domain.strip().lower())
    print(json.dumps(result.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
