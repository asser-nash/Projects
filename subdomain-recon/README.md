# SubRecon

A passive + active subdomain reconnaissance tool, built as a learning project
for ethical hacking / bug bounty work.

## What it does

1. **Passive recon**: Queries [crt.sh](https://crt.sh) (Certificate Transparency logs)
   to find every subdomain that has ever had a TLS certificate issued for it.
   This never sends a single packet to the target — it's just reading public logs.

2. **Active recon**: Brute-forces DNS using a wordlist, resolving each
   `candidate.target.com` concurrently. This *does* send traffic to DNS
   resolvers, so it should only be run against domains you're authorized to test.

## Why this is a useful portfolio project

Subdomain enumeration is genuinely the first step in most real pentests and
bug bounty engagements — finding the full attack surface before testing
anything. This tool demonstrates:

- Working with public APIs (crt.sh's JSON endpoint)
- Concurrent programming (ThreadPoolExecutor for DNS resolution)
- Basic OPSEC awareness (separating passive vs. active recon)
- Clean CLI design with argparse
- JSON reporting for handoff to other tools

## Usage

```bash
# Passive-only (always safe, no authorization prompt needed)
python3 subrecon.py example.com --passive-only

# Passive + active brute-force (requires confirmation)
python3 subrecon.py example.com -w wordlist_small.txt

# Skip the confirmation prompt (use carefully, e.g. in CI for your own domain)
python3 subrecon.py example.com -w wordlist_small.txt -y

# Custom output path and thread count
python3 subrecon.py example.com -w wordlist_small.txt -o report.json --threads 50
```

## Legal / Ethical Use

- The **passive mode** (crt.sh lookup) queries a public third-party log and
  is widely considered safe, low-impact reconnaissance.
- The **active mode** (DNS brute-force) sends real traffic to DNS servers.
  **Only run this against domains you own or have explicit written
  authorization to test** (e.g. a signed pentest scope, or a bug bounty
  program's documented scope).
- Unauthorized scanning of systems you don't own may violate laws like the
  Computer Fraud and Abuse Act (US) or equivalent legislation elsewhere.

## Possible extensions (good "v2" ideas for your portfolio)

- Add more passive sources (e.g. public DNS datasets, search engine dorking)
- Add HTTP probing on discovered subdomains (status code, title, tech stack)
- Add screenshot capture of live web subdomains
- Rate-limiting / jitter for the active brute-force to be less noisy
- Support for wildcard DNS detection (to avoid false positives)

## Requirements

- Python 3.8+
- No third-party packages — uses only the standard library
  (`urllib`, `socket`, `concurrent.futures`, `json`, `argparse`)
