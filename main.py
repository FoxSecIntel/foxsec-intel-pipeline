#!/usr/bin/env python3
"""foxsec-intel-pipeline

Domain enrichment and risk scoring for analyst triage.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any
from urllib.request import Request, urlopen


# Placeholder lists. Keep these curated over time.
HIGH_RISK_ASNS = {
    "AS9009",   # M247 (example placeholder)
    "AS14061",  # DigitalOcean (example placeholder)
    "AS16276",  # OVH (example placeholder)
}

TRUSTED_CLOUD_ASNS = {
    "AS13335",  # Cloudflare
    "AS16509",  # Amazon
    "AS15169",  # Google
    "AS8075",   # Microsoft
}

GEO_HIGH_RISK_COUNTRY_CODES = {"IR", "RU", "CN", "KP"}

# Placeholder set. Keep this curated with threat intel inputs.
BULLETPROOF_OR_ABUSE_TOLERANT_ASNS = {
    "AS9009",
    "AS20473",
    "AS49505",
}

BULLETPROOF_PROVIDER_KEYWORDS = {
    "bulletproof",
    "ddos-guard",
    "offshore",
    "abuse",
}

BRAND_NAMES = [
    "paypal",
    "microsoft",
    "amazon",
    "google",
    "apple",
    "facebook",
    "instagram",
    "linkedin",
    "dropbox",
    "netflix",
]

PHISHING_KEYWORDS = {"login", "secure", "verify", "account", "update", "billing", "support", "auth"}

TRUSTED_DNS_PATTERNS = [
    "cloudflare.com",
    "awsdns",
    "googledomains.com",
    "google.com",
    "azure-dns",
]


@dataclass
class SignalResult:
    payload: dict[str, Any]
    risk_points: int


def run(cmd: list[str], timeout: int = 8) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def dig_short(record_type: str, name: str) -> list[str]:
    rc, out, _ = run(["dig", "+time=2", "+tries=1", "+short", record_type, name], timeout=6)
    if rc != 0 or not out:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def normalise_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    return d


def extract_sld_label(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def resolve_ips(domain: str) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return sorted(set(ips))
    except socket.gaierror:
        return []


def parse_whois_date(raw: str) -> datetime | None:
    patterns = [
        r"Creation Date:\s*(.+)",
        r"Created On:\s*(.+)",
        r"Domain Registration Date:\s*(.+)",
        r"Registered On:\s*(.+)",
    ]

    candidate = None
    for pattern in patterns:
        m = re.search(pattern, raw, flags=re.I)
        if m:
            candidate = m.group(1).strip().split("\n")[0].strip()
            break

    if not candidate:
        return None

    candidate = candidate.replace("Z", "+00:00")

    known_formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d.%m.%Y",
    ]

    # Try ISO first
    try:
        dt = datetime.fromisoformat(candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass

    for fmt in known_formats:
        try:
            dt = datetime.strptime(candidate, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue

    return None


def format_age(age_days: int) -> tuple[int, int, str]:
    years = age_days // 365
    days = age_days % 365
    label = f"{years} years, {days} days"
    return years, days, label


def check_domain_age(domain: str) -> SignalResult:
    rc, out, err = run(["whois", domain], timeout=12)
    risk = 0
    age_days = None

    if rc == 0 and out:
        created = parse_whois_date(out)
        if created:
            age_days = (datetime.now(timezone.utc) - created).days

    if age_days is None:
        # Unknown domain age should be mildly suspicious but not catastrophic.
        risk += 10
        return SignalResult(
            {
                "domain_age_days": None,
                "domain_age_years": None,
                "domain_age_remaining_days": None,
                "domain_age_human": "unknown",
                "risk_points": risk,
                "error": "whois_unavailable",
            },
            risk,
        )

    years, rem_days, age_human = format_age(age_days)

    if age_days < 7:
        risk += 40
    elif age_days < 30:
        risk += 20
    elif age_days > 365:
        risk -= 20

    return SignalResult(
        {
            "domain_age_days": age_days,
            "domain_age_years": years,
            "domain_age_remaining_days": rem_days,
            "domain_age_human": age_human,
            "risk_points": risk,
        },
        risk,
    )


def normalise_for_typosquat(label: str) -> str:
    # Common obfuscation normalisation.
    return (
        label.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("7", "t")
        .replace("-", "")
    )


def check_typosquat(domain: str, brands: list[str]) -> SignalResult:
    label = extract_sld_label(domain)
    normalised_label = normalise_for_typosquat(label)

    best_brand = None
    best_score = 0.0

    for brand in brands:
        score = SequenceMatcher(None, normalised_label, brand).ratio()
        if score > best_score:
            best_score = score
            best_brand = brand

    contains_brand = any(brand in normalised_label for brand in brands)
    detected = (best_score > 0.85) or contains_brand
    risk = 50 if detected else 0

    keyword_hits = [k for k in PHISHING_KEYWORDS if k in domain.lower()]
    if keyword_hits:
        risk += min(20, len(keyword_hits) * 8)

    return SignalResult(
        {
            "typosquat_detected": detected,
            "matched_brand": best_brand if detected else None,
            "similarity_score": round(best_score, 4),
            "phishing_keywords": sorted(keyword_hits),
            "risk_points": risk,
        },
        risk,
    )


def check_email_security(domain: str) -> SignalResult:
    risk = 0

    txt_records = [r.replace('"', "") for r in dig_short("TXT", domain)]
    spf_present = any("v=spf1" in record.lower() for record in txt_records)

    dmarc_txt = [r.replace('"', "") for r in dig_short("TXT", f"_dmarc.{domain}")]
    dmarc_record = next((r for r in dmarc_txt if "v=dmarc1" in r.lower()), None)

    dmarc_policy = "missing"
    if dmarc_record:
        m = re.search(r"\bp=([a-zA-Z]+)", dmarc_record, flags=re.I)
        if m:
            pol = m.group(1).lower()
            if pol in ("none", "quarantine", "reject"):
                dmarc_policy = pol
            else:
                dmarc_policy = "missing"

    if dmarc_policy == "missing":
        risk += 20
    elif dmarc_policy == "none":
        risk += 10
    elif dmarc_policy == "reject":
        risk -= 20

    if not spf_present:
        risk += 10

    return SignalResult(
        {
            "spf_present": spf_present,
            "dmarc_policy": dmarc_policy,
            "risk_points": risk,
        },
        risk,
    )


def enrich_asn(ip: str) -> tuple[str | None, str | None, str | None]:
    req = Request(f"https://api.bgpview.io/ip/{ip}", headers={"User-Agent": "foxsec-intel-pipeline/0.2"})
    try:
        with urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8", errors="ignore"))
        prefixes = (data.get("data") or {}).get("prefixes") or []
        if prefixes:
            asn_obj = prefixes[0].get("asn") or {}
            asn_id = asn_obj.get("asn")
            provider = asn_obj.get("description")
            country_code = asn_obj.get("country_code")
            if asn_id:
                return f"AS{asn_id}", provider, country_code
    except Exception:
        pass

    # Team Cymru fallback.
    try:
        octets = ip.split(".")
        if len(octets) == 4:
            query = ".".join(reversed(octets)) + ".origin.asn.cymru.com"
            txt = [r.replace('"', "") for r in dig_short("TXT", query)]
            if txt:
                parts = [p.strip() for p in txt[0].split("|")]
                if parts and parts[0].isdigit():
                    return f"AS{parts[0]}", "Unknown", None
    except Exception:
        pass

    return None, None, None


def check_asn_reputation(domain: str) -> SignalResult:
    ips = resolve_ips(domain)
    ip = ips[0] if ips else None

    asn = None
    provider = None
    country_code = None
    risk = 0

    if ip:
        asn, provider, country_code = enrich_asn(ip)

    bulletproof_flag = False
    if asn in BULLETPROOF_OR_ABUSE_TOLERANT_ASNS:
        risk += 25
        bulletproof_flag = True

    provider_text = (provider or "").lower()
    if any(k in provider_text for k in BULLETPROOF_PROVIDER_KEYWORDS):
        risk += 25
        bulletproof_flag = True

    if asn in HIGH_RISK_ASNS:
        risk += 20

    country_risk_flag = False
    if country_code and country_code.upper() in GEO_HIGH_RISK_COUNTRY_CODES:
        risk += 20
        country_risk_flag = True

    if asn in TRUSTED_CLOUD_ASNS and not bulletproof_flag and not country_risk_flag:
        risk -= 10

    return SignalResult(
        {
            "ip": ip,
            "asn": asn,
            "provider": provider,
            "country_code": country_code,
            "country_risk_flag": country_risk_flag,
            "bulletproof_hosting_flag": bulletproof_flag,
            "risk_points": risk,
        },
        risk,
    )


def looks_trusted_ns(ns: str) -> bool:
    lowered = ns.lower()
    return any(pattern in lowered for pattern in TRUSTED_DNS_PATTERNS)


def check_dns_infrastructure(domain: str) -> SignalResult:
    risk = 0

    mx = dig_short("MX", domain)
    mx_present = len(mx) > 0

    ns_records = [n.rstrip(".").lower() for n in dig_short("NS", domain)]
    trusted_dns_provider = any(looks_trusted_ns(ns) for ns in ns_records)

    if not mx_present:
        risk += 10

    if trusted_dns_provider:
        risk -= 10
    elif ns_records:
        risk += 10

    return SignalResult(
        {
            "mx_present": mx_present,
            "nameservers": ns_records,
            "trusted_dns_provider": trusted_dns_provider,
            "risk_points": risk,
        },
        risk,
    )


def calculate_signal_confidence(signals: dict[str, dict[str, Any]]) -> dict[str, int]:
    confidence: dict[str, int] = {}

    confidence["domain_age"] = 90 if signals.get("domain_age", {}).get("domain_age_days") is not None else 40
    confidence["typosquat"] = 85

    email = signals.get("email_security", {})
    email_checks = int(email.get("spf_present") is not None) + int(email.get("dmarc_policy") != "missing")
    confidence["email_security"] = 50 + (email_checks * 20)

    asn = signals.get("asn_reputation", {})
    asn_checks = int(asn.get("asn") is not None) + int(asn.get("country_code") is not None)
    confidence["asn_reputation"] = 40 + (asn_checks * 25)

    dns = signals.get("dns_quality", {})
    confidence["dns_quality"] = 80 if dns.get("nameservers") else 45

    return confidence


def calculate_risk_score(signals: dict[str, dict[str, Any]]) -> tuple[int, str, dict[str, int]]:
    # Keep each signal contribution in a sensible range.
    # This avoids one noisy signal fully dominating the final score.
    capped: dict[str, int] = {}
    for name, signal_data in signals.items():
        points = int(signal_data.get("risk_points", 0))
        capped[name] = max(min(points, 50), -20)

    total = sum(capped.values())

    # Mild uncertainty uplift when critical data is missing.
    uncertainty_penalty = 0
    if signals.get("domain_age", {}).get("domain_age_days") is None:
        uncertainty_penalty += 5
    if signals.get("asn_reputation", {}).get("asn") is None:
        uncertainty_penalty += 5

    total += uncertainty_penalty

    # Keep score non-negative for easier reporting.
    total = max(total, 0)

    if total >= 60:
        level = "HIGH"
    elif total >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    breakdown = dict(capped)
    if uncertainty_penalty:
        breakdown["uncertainty"] = uncertainty_penalty

    return total, level, breakdown


def analyse_domain(domain: str) -> dict[str, Any]:
    domain = normalise_domain(domain)

    domain_age = check_domain_age(domain)
    typosquat = check_typosquat(domain, BRAND_NAMES)
    email_security = check_email_security(domain)
    asn_reputation = check_asn_reputation(domain)
    dns_quality = check_dns_infrastructure(domain)

    signals = {
        "domain_age": domain_age.payload,
        "typosquat": typosquat.payload,
        "email_security": email_security.payload,
        "asn_reputation": asn_reputation.payload,
        "dns_quality": dns_quality.payload,
    }

    score, level, breakdown = calculate_risk_score(signals)
    confidence = calculate_signal_confidence(signals)

    return {
        "domain": domain,
        "signals": signals,
        "signal_confidence": confidence,
        "risk_breakdown": breakdown,
        "risk_score": score,
        "risk_level": level,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="foxsec-intel-pipeline domain risk scorer")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--output", choices=["json"], default="json", help="Output format")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = analyse_domain(args.domain)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
