# DNS Dangling Scanner for Kubernetes SIG Security

`dns_scan.py` is a **proactive scanner for dangling DNS records pointing to Netlify**, designed for use within the Kubernetes SIG Security tooling ecosystem. It helps prevent **subdomain takeover attacks** by detecting DNS records that point to non-existent Netlify sites.

---

## Table of Contents

- [Key Features](#key-features)
- [Security Notes](#security-notes)
- [Requirements](#requirements)
- [YAML DNS Records Format](#yaml-dns-records-format)
- [Usage](#usage)
- [Output](#output)
- [Contribution](#contribution)

---

## Key Features

- **Safe network requests** with retries and timeout
- **Signature-based detection** for non-existent Netlify sites
- **JSON structured output** for CI / Prow integration
- **Detailed logging** for auditing and debugging
- **Fail-safe design**: network failures assume existence to avoid false positives
- **Exit codes** for automation workflows

## Security Notes

- This scanner is strictly **passive**.
- It **does NOT modify, claim, or interact** with third-party resources beyond an HTTP GET.
- Designed to be **safe for CI/CD pipelines** and periodic scans.

## Requirements

The scanner depends on:

- Python 3.10+  
- [PyYAML](https://pypi.org/project/PyYAML/) >=6.0  
- [requests](https://pypi.org/project/requests/) >=2.31  

Install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## YAML DNS Records Format

The scanner expects a YAML file with the following structure:

```json
records:
  - hostname: "docs.k8s.io"
    target: "kubernetes-docs.netlify.app"
  - hostname: "dangling.k8s.io"
    target: "definitely-not-existing-k8s.netlify.app"
  - hostname: "old-preview.k8s.io"
    target: "old-k8s-preview-123.netlify.app"
```

- hostname → the DNS record name being checked
- target → the destination the DNS points to
- Any record missing hostname or target is skipped

Tip: Keep examples in examples/dns_records.yaml for testing.

## Usage

Run the scanner via Python:

```bash
python3 dns_scan.py <path_to_dns_records.yaml>
```

Example:

```bash
python3 sig-security-tooling/scan-dangling-dns/dns_scan.py sig-security-tooling/scan-dangling-dns/examples/dns_records.yaml
```

## Output

The scanner produces:

- Detailed logs (INFO for checks, ERROR for dangling)
- JSON structured output listing all dangling records

Example JSON output:

```json
[
  {
    "hostname": "dangling.k8s.io",
    "target": "definitely-not-existing-k8s.netlify.app",
    "provider": "netlify"
  }
]
```

## Contribution

- Follow the CONTRIBUTING.md guidelines
- Ensure new DNS providers or checks include fail-safe behavior
- Maintain logging and JSON output consistency
