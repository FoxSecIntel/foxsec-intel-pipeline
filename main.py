#!/usr/bin/env python3
"""foxsec-intel-pipeline

Domain enrichment and risk scoring for analyst triage.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


DEFAULT_RISK_PROFILE = {
    "geo_high_risk_country_codes": ["IR", "RU", "CN", "KP"],
    "high_risk_asns": ["AS9009", "AS14061", "AS16276"],
    "trusted_cloud_asns": ["AS13335", "AS16509", "AS15169", "AS8075"],
    "bulletproof_or_abuse_tolerant_asns": ["AS9009", "AS20473", "AS49505"],
    "bulletproof_provider_keywords": ["bulletproof", "ddos-guard", "offshore", "abuse"],
    "brand_names": [
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
    ],
    "phishing_keywords": ["login", "secure", "verify", "account", "update", "billing", "support", "auth"],
    "trusted_dns_patterns": ["cloudflare.com", "awsdns", "googledomains.com", "google.com", "azure-dns"],
}


def load_risk_profile(config_path: str | None = None) -> dict[str, Any]:
    base = dict(DEFAULT_RISK_PROFILE)

    if config_path:
        candidate = Path(config_path)
    else:
        candidate = Path(__file__).resolve().parent / "config" / "risk_profiles.json"

    if not candidate.exists():
        return base

    try:
        with candidate.open("r", encoding="utf-8") as f:
            loaded = json.load(f)
        for key, value in loaded.items():
            if key in base and isinstance(value, list):
                base[key] = value
    except Exception:
        return base

    return base


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


def check_typosquat(domain: str, brands: list[str], phishing_keywords: set[str]) -> SignalResult:
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

    keyword_hits = [k for k in phishing_keywords if k in domain.lower()]
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


def check_asn_reputation(
    domain: str,
    high_risk_asns: set[str],
    trusted_cloud_asns: set[str],
    geo_high_risk_country_codes: set[str],
    bulletproof_or_abuse_tolerant_asns: set[str],
    bulletproof_provider_keywords: set[str],
) -> SignalResult:
    ips = resolve_ips(domain)
    ip = ips[0] if ips else None

    asn = None
    provider = None
    country_code = None
    risk = 0

    if ip:
        asn, provider, country_code = enrich_asn(ip)

    bulletproof_flag = False
    if asn in bulletproof_or_abuse_tolerant_asns:
        risk += 25
        bulletproof_flag = True

    provider_text = (provider or "").lower()
    if any(k in provider_text for k in bulletproof_provider_keywords):
        risk += 25
        bulletproof_flag = True

    if asn in high_risk_asns:
        risk += 20

    country_risk_flag = False
    if country_code and country_code.upper() in geo_high_risk_country_codes:
        risk += 20
        country_risk_flag = True

    if asn in trusted_cloud_asns and not bulletproof_flag and not country_risk_flag:
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


def looks_trusted_ns(ns: str, trusted_dns_patterns: list[str]) -> bool:
    lowered = ns.lower()
    return any(pattern in lowered for pattern in trusted_dns_patterns)


def check_dns_infrastructure(domain: str, trusted_dns_patterns: list[str]) -> SignalResult:
    risk = 0

    mx = dig_short("MX", domain)
    mx_present = len(mx) > 0

    ns_records = [n.rstrip(".").lower() for n in dig_short("NS", domain)]
    trusted_dns_provider = any(looks_trusted_ns(ns, trusted_dns_patterns) for ns in ns_records)

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


def analyse_domain(domain: str, profile: dict[str, Any]) -> dict[str, Any]:
    domain = normalise_domain(domain)

    brand_names = [str(x).lower() for x in profile.get("brand_names", [])]
    phishing_keywords = {str(x).lower() for x in profile.get("phishing_keywords", [])}
    high_risk_asns = {str(x).upper() for x in profile.get("high_risk_asns", [])}
    trusted_cloud_asns = {str(x).upper() for x in profile.get("trusted_cloud_asns", [])}
    geo_high_risk_country_codes = {str(x).upper() for x in profile.get("geo_high_risk_country_codes", [])}
    bulletproof_or_abuse_tolerant_asns = {str(x).upper() for x in profile.get("bulletproof_or_abuse_tolerant_asns", [])}
    bulletproof_provider_keywords = {str(x).lower() for x in profile.get("bulletproof_provider_keywords", [])}
    trusted_dns_patterns = [str(x).lower() for x in profile.get("trusted_dns_patterns", [])]

    domain_age = check_domain_age(domain)
    typosquat = check_typosquat(domain, brand_names, phishing_keywords)
    email_security = check_email_security(domain)
    asn_reputation = check_asn_reputation(
        domain,
        high_risk_asns,
        trusted_cloud_asns,
        geo_high_risk_country_codes,
        bulletproof_or_abuse_tolerant_asns,
        bulletproof_provider_keywords,
    )
    dns_quality = check_dns_infrastructure(domain, trusted_dns_patterns)

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


def result_to_row(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": result.get("domain"),
        "risk_score": result.get("risk_score"),
        "risk_level": result.get("risk_level"),
        "dmarc_policy": result.get("signals", {}).get("email_security", {}).get("dmarc_policy"),
        "spf_present": result.get("signals", {}).get("email_security", {}).get("spf_present"),
        "asn": result.get("signals", {}).get("asn_reputation", {}).get("asn"),
        "provider": result.get("signals", {}).get("asn_reputation", {}).get("provider"),
        "country_code": result.get("signals", {}).get("asn_reputation", {}).get("country_code"),
        "mx_present": result.get("signals", {}).get("dns_quality", {}).get("mx_present"),
        "typosquat_detected": result.get("signals", {}).get("typosquat", {}).get("typosquat_detected"),
    }


def render_csv(results: list[dict[str, Any]]) -> str:
    from io import StringIO

    rows = [result_to_row(r) for r in results]
    if not rows:
        return ""

    fieldnames = list(rows[0].keys())
    buff = StringIO()
    writer = csv.DictWriter(buff, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buff.getvalue().strip()


def render_markdown(results: list[dict[str, Any]]) -> str:
    if not results:
        return "# foxsec-intel-pipeline summary\n\nNo results."

    if len(results) == 1:
        result = results[0]
        signals = result.get("signals", {})
        email = signals.get("email_security", {})
        asn = signals.get("asn_reputation", {})
        dns = signals.get("dns_quality", {})
        ty = signals.get("typosquat", {})
        age = signals.get("domain_age", {})

        lines = [
            f"# foxsec-intel-pipeline summary: {result.get('domain')}",
            "",
            f"- Risk score: **{result.get('risk_score')}**",
            f"- Risk level: **{result.get('risk_level')}**",
            f"- Domain age: {age.get('domain_age_human', 'unknown')}",
            f"- DMARC policy: {email.get('dmarc_policy')}",
            f"- SPF present: {email.get('spf_present')}",
            f"- ASN: {asn.get('asn')}",
            f"- Provider: {asn.get('provider')}",
            f"- Country: {asn.get('country_code')}",
            f"- MX present: {dns.get('mx_present')}",
            f"- Typosquat detected: {ty.get('typosquat_detected')}",
        ]

        keywords = ty.get("phishing_keywords") or []
        if keywords:
            lines.append(f"- Phishing keywords: {', '.join(keywords)}")

        lines.append("")
        lines.append("## Risk breakdown")
        for k, v in (result.get("risk_breakdown") or {}).items():
            lines.append(f"- {k}: {v}")
        return "\n".join(lines)

    lines = ["# foxsec-intel-pipeline batch summary", "", "| Domain | Risk Score | Risk Level | DMARC | SPF | ASN |", "|---|---:|---|---|---|---|"]
    for r in results:
        row = result_to_row(r)
        lines.append(
            f"| {row['domain']} | {row['risk_score']} | {row['risk_level']} | {row['dmarc_policy']} | {row['spf_present']} | {row['asn'] or 'unknown'} |"
        )
    return "\n".join(lines)


def build_key_findings(result: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    signals = result.get("signals", {})

    email = signals.get("email_security", {})
    if not email.get("spf_present"):
        findings.append("No SPF record detected")
    if email.get("dmarc_policy") in ("missing", "none"):
        findings.append(f"DMARC policy is {email.get('dmarc_policy')}")

    ty = signals.get("typosquat", {})
    if ty.get("typosquat_detected"):
        findings.append("Typosquat indicators detected")

    asn = signals.get("asn_reputation", {})
    if asn.get("country_risk_flag"):
        findings.append("Hosted in high-risk country profile")
    if asn.get("bulletproof_hosting_flag"):
        findings.append("Potential bulletproof-hosting signal detected")

    if not findings:
        findings.append("No major risk indicators triggered")

    return findings[:5]


def render_html(results: list[dict[str, Any]]) -> str:
    if not results:
        return "<!doctype html><html><body><h1>No results</h1></body></html>"

    rows_html = []
    panels_html = []

    for r in results:
        row = result_to_row(r)
        level = str(row["risk_level"]).upper()
        level_class = {"LOW": "level-low", "MEDIUM": "level-medium", "HIGH": "level-high"}.get(level, "")

        rows_html.append(
            "<tr>"
            f"<td>{html.escape(str(row['domain']))}</td>"
            f"<td>{html.escape(str(row['risk_score']))}</td>"
            f"<td><span class='pill {level_class}'>{html.escape(level)}</span></td>"
            f"<td>{html.escape(str(row['dmarc_policy']))}</td>"
            f"<td>{html.escape(str(row['spf_present']))}</td>"
            f"<td>{html.escape(str(row['asn'] or 'unknown'))}</td>"
            "</tr>"
        )

        top_signals = sorted((r.get("risk_breakdown") or {}).items(), key=lambda x: x[1], reverse=True)[:3]
        signal_lines = "".join(
            f"<li>{html.escape(str(k))}: {html.escape(str(v))}</li>" for k, v in top_signals
        ) or "<li>None</li>"

        findings = build_key_findings(r)
        findings_html = "".join(f"<li>{html.escape(item)}</li>" for item in findings)

        panels_html.append(
            "<div class='summary-card'>"
            f"<h3>{html.escape(str(r.get('domain')))}</h3>"
            f"<p>Risk Level: <span class='pill {level_class}'>{html.escape(level)}</span></p>"
            f"<p>Risk Score: <strong>{html.escape(str(r.get('risk_score')))}</strong></p>"
            "<p><strong>Top contributing signals</strong></p>"
            f"<ul>{signal_lines}</ul>"
            "<p><strong>Key findings</strong></p>"
            f"<ul>{findings_html}</ul>"
            "</div>"
        )

    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>foxsec-intel-pipeline</title>"
        "<style>body{font-family:Arial,sans-serif;max-width:1080px;margin:24px auto;padding:0 12px;}"
        "h1{font-size:22px} .card{border:1px solid #ddd;border-radius:8px;padding:16px}"
        ".summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:16px}"
        ".summary-card{border:1px solid #ddd;border-radius:8px;padding:12px;background:#fafafa}"
        ".pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700}"
        ".level-low{background:#e7f7ec;color:#1f7a3f}"
        ".level-medium{background:#fff4e5;color:#a35a00}"
        ".level-high{background:#ffe8e8;color:#a10000}"
        "table{width:100%;border-collapse:collapse} th,td{border:1px solid #ddd;padding:8px;text-align:left}"
        "th{background:#f5f5f5} li{margin:4px 0}</style></head><body>"
        f"<h1>foxsec-intel-pipeline batch report ({len(results)} domains)</h1>"
        f"<div class='summary-grid'>{''.join(panels_html)}</div>"
        "<div class='card'><table><thead><tr><th>Domain</th><th>Risk Score</th><th>Risk Level</th><th>DMARC</th><th>SPF</th><th>ASN</th></tr></thead><tbody>"
        f"{''.join(rows_html)}"
        "</tbody></table></div></body></html>"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="foxsec-intel-pipeline domain risk scorer")
    parser.add_argument("--domain", required=False, help="Single target domain")
    parser.add_argument("--input-file", required=False, help="Batch input file with one domain per line")
    parser.add_argument("--output", choices=["json", "csv", "markdown", "html"], default="json", help="Output format")
    parser.add_argument("--risk-config", default=None, help="Path to risk profile JSON file")
    return parser.parse_args()


def load_domains_from_file(path: str) -> list[str]:
    domains: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            item = line.strip()
            if not item or item.startswith("#"):
                continue
            domains.append(item)
    return domains


def main() -> int:
    args = parse_args()
    if not args.domain and not args.input_file:
        print("Error: provide --domain or --input-file", file=sys.stderr)
        return 2

    profile = load_risk_profile(args.risk_config)

    targets: list[str] = []
    if args.domain:
        targets.append(args.domain)
    if args.input_file:
        targets.extend(load_domains_from_file(args.input_file))

    # de-duplicate while preserving order
    seen = set()
    deduped = []
    for t in targets:
        n = normalise_domain(t)
        if n in seen:
            continue
        seen.add(n)
        deduped.append(n)

    results = [analyse_domain(d, profile) for d in deduped]

    if args.output == "json":
        if len(results) == 1 and args.domain and not args.input_file:
            print(json.dumps(results[0], indent=2))
        else:
            print(json.dumps({"count": len(results), "results": results}, indent=2))
    elif args.output == "csv":
        print(render_csv(results))
    elif args.output == "markdown":
        print(render_markdown(results))
    elif args.output == "html":
        print(render_html(results))

    return 0


if __name__ == "__main__":
    sys.exit(main())
