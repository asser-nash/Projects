# SubRecon

a passive + active subdomain reconnaissance tool, built as a learning project
for ethical hacking / bug bounty work.

## What it does

1. **passive recon**: Queries [crt.sh](https://crt.sh) (Certificate Transparency logs)
   to find every subdomain that has ever had a TLS certificate issued for it.
   this never sends a single packet to the target — it's just reading public logs.

2. **active recon**: brute-forces DNS using a wordlist, resolving each
   `candidate.target.com` concurrently. this *does* send traffic to DNS
   resolvers, so it should only be run against domains you're authorized to test.

## why this is a useful portfolio project

subdomain enumeration is genuinely the first step in most real pentests and
bug bounty engagements — finding the full attack surface before testing
anything. This tool demonstrates:

- working with public APIs (crt.sh's JSON endpoint)
- concurrent programming (ThreadPoolExecutor for DNS resolution)
- basic OPSEC awareness (separating passive vs. active recon)
- clean CLI design with argparse
- JSON reporting for handoff to other tools

## usage

```bash
# passive-only (always safe, no authorization prompt needed)
python3 subrecon.py example.com --passive-only

# passive + active brute-force (requires confirmation)
python3 subrecon.py example.com -w wordlist_small.txt

# skip the confirmation prompt (use carefully, e.g. in CI for your own domain)
python3 subrecon.py example.com -w wordlist_small.txt -y

# custom output path and thread count
python3 subrecon.py example.com -w wordlist_small.txt -o report.json --threads 50
```

## legal / ethical Use

- the **passive mode** (crt.sh lookup) queries a public third-party log and
  is widely considered safe, low-impact reconnaissance.
- the **active mode** (DNS brute-force) sends real traffic to DNS servers.
  **only run this against domains you own or have explicit written
  authorization to test** (e.g. a signed pentest scope, or a bug bounty
  program's documented scope).
- unauthorized scanning of systems you don't own may violate laws like the
  Computer Fraud and Abuse Act (US) or equivalent legislation elsewhere.

## possible extensions (good "v2" ideas for your portfolio)

- add more passive sources (e.g. public DNS datasets, search engine dorking)
- add HTTP probing on discovered subdomains (status code, title, tech stack)
- add screenshot capture of live web subdomains
- rate-limiting / jitter for the active brute-force to be less noisy
- support for wildcard DNS detection (to avoid false positives)

## requirements

- python 3.8+
- no third-party packages — uses only the standard library
  (`urllib`, `socket`, `concurrent.futures`, `json`, `argparse`)
