#!/usr/bin/env python3

"""
dns_scan.py

Proactive scanner for dangling DNS records pointing to Netlify.
Detects subdomain takeovers where the DNS points to a Netlify site
that does not exist.

Key features:
- Safe retries for network failures
- Signature-based detection of non-existent Netlify sites
- JSON structured output for CI/Prow integration
- Logging for auditing and debugging
"""

# SECURITY NOTE:
# This scanner is strictly passive.
# It does NOT attempt to claim, modify, or interact with third-party resources
# beyond a simple HTTP GET for existence validation.

import yaml
import requests
import logging
import sys
import json
from typing import List, Dict
from urllib.parse import urlparse

# Security and scan settings
HTTP_TIMEOUT = 5             # Timeout for HTTP requests (seconds)
MAX_RETRIES = 2              # Number of retry attempts for transient errors
USER_AGENT = "k8s-dns-security-scan/1.1"
MAX_REDIRECTS = 3            # Limit excessive redirects
MAX_BODY_CHARS = 2000        # Read only first N chars of body to avoid memory issues

# Known textual signatures of a dangling Netlify site
NETLIFY_DANGLING_SIGNATURES = [
    "Not Found - Request ID",
    "Site not found",
    "Looks like you’ve followed a broken link"
]

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Load DNS records from YAML
def load_dns_records(path: str) -> List[Dict]:
    """
    Load DNS records from a YAML file.
    Expects a top-level key "records" containing a list of dictionaries
    with at least 'hostname' and 'target' keys.
    """
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("records", [])
    except Exception as e:
        logging.error(f"Failed to load DNS records: {e}")
        sys.exit(1)

# Utility functions
def is_netlify_target(target: str) -> bool:
    """Check if a target points to Netlify."""
    return target.endswith(".netlify.app")

def normalize_hostname(target: str) -> str:
    """
    Normalize target to a clean hostname.
    Removes schema (http/https) and extra slashes.
    """
    parsed = urlparse(target if target.startswith("http") else f"https://{target}")
    return parsed.netloc

# Netlify dangling check
def check_netlify_site(hostname: str) -> bool:
    """
    Check if the Netlify site exists.

    Returns:
        True  -> site exists
        False -> strong indication of dangling (site not found)
    
    Retries up to MAX_RETRIES in case of transient network failures.
    Fail-safe: assume site exists if all retries fail.
    """
    url = f"https://{hostname}"
    headers = {"User-Agent": USER_AGENT}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True
            )

            # Avoid false positives due to excessive redirects
            if len(resp.history) > MAX_REDIRECTS:
                logging.warning(f"Too many redirects for {hostname}")
                return True

            body = resp.text[:MAX_BODY_CHARS]  # limit memory usage

            # Detect known dangling signatures
            for signature in NETLIFY_DANGLING_SIGNATURES:
                if signature.lower() in body.lower():
                    return False

            return True

        except requests.RequestException as e:
            logging.warning(f"Attempt {attempt} failed for {hostname}: {e}")
            if attempt == MAX_RETRIES:
                logging.warning(f"Giving up on {hostname}, assuming it exists")
                return True  # fail safe

    return True

# Scan all DNS records
def scan_dns_records(records: List[Dict]) -> List[Dict]:
    """
    Iterate over all DNS records and detect dangling Netlify records.
    Returns a list of dangling entries with hostname, target, and provider.
    """
    dangling = []

    for record in records:
        hostname = record.get("hostname")
        target = record.get("target")

        if not hostname or not target:
            continue  # skip invalid records

        if is_netlify_target(target):
            normalized = normalize_hostname(target)
            logging.info(f"Checking Netlify target: {hostname} -> {normalized}")

            exists = check_netlify_site(normalized)

            if not exists:
                # Log explicit dangling detection for audit
                logging.error(f"Dangling Netlify DNS detected: {hostname} -> {target}")

                # Add to dangling list
                dangling.append({
                    "hostname": hostname,
                    "target": target,
                    "provider": "netlify"
                })

    return dangling

# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: dns_scan.py <dns_records.yaml>")
        sys.exit(1)

    dns_file = sys.argv[1]
    records = load_dns_records(dns_file)
    dangling = scan_dns_records(records)

    # Structured output for CI/Prow integration
    if dangling:
        logging.error("Dangling DNS records detected:")
        print(json.dumps(dangling, indent=2))
        sys.exit(2)  # exit code for CI failure
    else:
        logging.info("No dangling DNS records found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
    """
    Exit codes:
      0 - No dangling DNS records found
      1 - Usage or input error
      2 - Dangling DNS records detected
    """