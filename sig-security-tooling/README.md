# Official CVE Feed

## Introduction

The **Kubernetes Official CVE Feed** provides an authoritative and machine-readable source of information about security vulnerabilities (CVEs) affecting Kubernetes.  
It helps developers, operators, and security professionals stay informed about officially recognized and triaged vulnerabilities in the Kubernetes ecosystem.

This feed is maintained by the **Kubernetes Security Response Committee (SRC)** and **SIG Security**, ensuring that all CVE data published is verified and accurately reflects the current security state of Kubernetes.

### Who Uses the Official CVE Feed

The feed serves multiple audiences:

- **Developers and maintainers** — to identify and track vulnerabilities related to their components or dependencies.  
- **Security teams and researchers** — to integrate verified Kubernetes CVE data into vulnerability management tools or monitoring systems.  
- **Cloud providers and Kubernetes distributors** — to automate tracking of upstream advisories and coordinate patching.  
- **End-users and operators** — to monitor official Kubernetes CVEs and apply security updates or mitigations accordingly.

### What It Provides

- A **JSON feed** listing all issues labeled as [`official-cve-feed`](https://github.com/kubernetes/kubernetes/issues?q=is%3Aissue+label%3Aofficial-cve-feed+) in the [kubernetes/kubernetes](https://github.com/kubernetes/kubernetes) repository.  
- An **HTML and RSS view** available at [k8s.io/docs/reference/issues-security/official-cve-feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/).  
  

Each entry in the feed corresponds to an official CVE affecting Kubernetes, such as:  
- [CVE-2023-5528](https://www.cve.org/CVERecord?id=CVE-2023-5528) — Kubernetes ingress-nginx controller vulnerability  
- [CVE-2023-3676](https://www.cve.org/CVERecord?id=CVE-2023-3676) — Kubernetes apiserver privilege escalation  
- [CVE-2021-25741](https://www.cve.org/CVERecord?id=CVE-2021-25741) — Symlink vulnerability in volume mounts  

---

## The official CVE feed is separated into two main components:
1. The scripts, that update a cloud bucket containing the feed.
2. The website, rendering and serving the feed in various formats.

---

### Scripts

A script in the [kubernetes/sig-security](https://github.com/kubernetes/sig-security)
repository under the [sig-security-tooling/cve-feed/hack](https://github.com/kubernetes/sig-security/tree/main/sig-security-tooling/cve-feed/hack)
folder. This script is a bash script named `fetch-cve-feed.sh` that:
- sets up the python3 environment;
- generates the CVE feed file with `fetch-official-cve-feed.py`;
- compares the sha256 of the newly generated file with the existing one;
- if the sha256 changed, uploads the newly generated CVE feed file to the bucket.

The `fetch-official-cve-feed.py` file executed by the `fetch-cve-feed.sh` is a
python3 script that:
- queries the GitHub API to fetch all the issues with the `official-cve-feed`
  label in the [kubernetes/kubernetes](https://github.com/kubernetes/kubernetes/issues?q=is%3Aissue%20label%3Aofficial-cve-feed%20)
  repository;
- formats the result with the appropriate JSON schema to be JSON feed
  compliant;
- prints the output to stdout.

These scripts are run regularly as a CronJob on the k8s infrastructure.

In short, these scripts take the GitHub [kubernetes/kubernetes issues
labeled with `official-cve-feed`](https://github.com/kubernetes/kubernetes/issues?q=is%3Aissue%20label%3Aofficial-cve-feed%20)
as the input and generate a JSON feed file as an output in a cloud bucket. The
output can be publicly fetched at [gs://k8s-cve-feed/](https://console.cloud.google.com/storage/browser/k8s-cve-feed) or [storage.googleapis.com/k8s-cve-feed](https://storage.googleapis.com/k8s-cve-feed/).

---

### Website

The main output of the official CVE feed is the HTML website page available on
[k8s.io/docs/reference/issues-security/official-cve-feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
where you can also find links to the JSON and RSS feed formats.

The corresponding HTML page is generated from the [official-cve-feed.md](https://github.com/kubernetes/website/blob/main/content/en/docs/reference/issues-security/official-cve-feed.md?plain=1)
file from the [kubernetes/website](https://github.com/kubernetes/website)
repository. It mainly calls the `cve-feed` shortcode that is defined in
[website/layouts/shortcodes/cve-feed.html](https://github.com/kubernetes/website/blob/main/layouts/shortcodes/cve-feed.html)
which consumes the JSON format by fetching the URL from the
[`.Site.Params.cveFeedBucket`](https://github.com/kubernetes/website/blob/75f19fc9675d07fdbc724d02953d905ef7ca8619/hugo.toml#L168)
and translating it to an HTML table.

This page is thus updated every time the website is built.

---

## References

- [Kubernetes Security Response Committee (SRC)](https://kubernetes.io/docs/reference/issues-security/security/#security-response-committee-src)  
- [Official CVE Feed – Kubernetes Docs](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)  
- [Kubernetes CVEs on CVE.org](https://www.cve.org/PartnerInformation/ListofPartners/partner/Kubernetes)  
- [Google Search: Kubernetes Official CVE Feed](https://www.google.com/search?q=Kubernetes+Official+CVE+Feed)
