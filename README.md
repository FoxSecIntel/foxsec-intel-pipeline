# foxsec-intel-pipeline

## Overview

`foxsec-intel-pipeline` is an analyst-first enrichment and scoring pipeline for security triage.

It takes a domain, IP, or URL artefact and produces a structured intelligence output that can be used in SOC workflows, reports, and automation.

Version 1 focuses on domain intelligence with:

- DNS resolution
- DMARC and SPF posture checks
- ASN and provider enrichment
- Basic risk scoring
- JSON output for downstream tooling

## Problem

Security analysts often waste valuable triage time jumping between tools to answer basic but critical questions:

- Is this domain configured like a legitimate sender
- Who owns the hosting network
- Does routing context increase risk
- Is this likely low risk, medium risk, or high risk

This project exists to standardise that first-pass enrichment and scoring into one repeatable workflow.

## Workflow

1. Accept a domain input
2. Resolve DNS and extract core records
3. Check DMARC and SPF posture
4. Enrich with ASN and provider information
5. Calculate a basic risk score
6. Output a structured analyst result in JSON

## Architecture

```text
Input (domain / IP / URL)

        ↓

   Collection Layer

        ↓

   Enrichment Layer

        ↓

  Analysis and Scoring

        ↓

 JSON / HTML / Analyst Report
```

## Example Usage

```bash
python foxsec_scan.py --domain example.com --output json
python foxsec_scan.py --domain example.com --output json --risk-config config/risk_profiles.json
```

## Optional shell alias

Add this to your `~/.bash_profile`:

```bash
alias foxscan='python3 ~/r/repos/foxsec-intel-pipeline/foxsec_scan.py'
```

Then reload your shell and run:

```bash
source ~/.bash_profile
foxscan --domain example.com --output json
```

## Example Output

```json
{
  "domain": "example.com",
  "dmarc": "present",
  "spf": "softfail",
  "asn": "AS13335",
  "provider": "Cloudflare",
  "risk_score": 28,
  "risk_level": "low"
}
```

## Roadmap

- v0.1: Domain pipeline (DNS, DMARC, SPF, ASN, score, JSON)
- v0.2: URL parsing and hostname extraction path
- v0.3: IP-first mode and reverse mapping context
- v0.4: HTML report renderer for analyst handoff
- v0.5: Batch mode and CSV input support
- v0.6: Confidence scoring and evidence weighting
- v0.7: Optional connectors for SIEM and SOAR

## Related Tools

- [BGP-Intel](https://github.com/FoxSecIntel/BGP-Intel): ASN and prefix exposure analysis
- [DNS-analysis](https://github.com/FoxSecIntel/DNS-analysis): DNS security posture checks
- [PhishSense](https://github.com/FoxSecIntel/PhishSense): Phishing analysis workflow tooling
- [WebPage-Analysis](https://github.com/FoxSecIntel/WebPage-Analysis): Web artefact analysis helpers
