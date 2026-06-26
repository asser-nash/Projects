#!/usr/bin/env python3
"""
SubRecon - Passive + Active Subdomain Reconnaissance Tool
============================================================

Combines two legitimate recon techniques used in authorized penetration
testing and bug bounty work:

  1. PASSIVE: Queries crt.sh (Certificate Transparency logs) to find
     subdomains that have ever had a TLS certificate issued for them.
     This is 100% passive - no traffic touches the target at all.

  2. ACTIVE: DNS brute-forcing using a wordlist, with concurrent
     resolution for speed. This DOES send traffic to DNS servers,
     so only run it against domains you're authorized to test.

LEGAL/ETHICAL NOTICE:
  Only use the active (DNS brute-force) mode against domains you own
  or have explicit written authorization to test. The passive mode
  queries a public, third-party log and is generally considered safe
  reconnaissance, but always respect scope agreements and program rules
  if you're doing this under a bug bounty.

Author: [your name]
License: MIT
"""

import argparse
import concurrent.futures
import json
import socket
import sys
import time
from dataclasses import dataclass, field
from urllib.request import urlopen, Request
from urllib.error import URLError


@dataclass
class ReconResult:
    domain: str
    passive_subdomains: set = field(default_factory=set)
    active_subdomains: dict = field(default_factory=dict)  # subdomain -> IP
    duration_seconds: float = 0.0


def banner():
    print(r"""
   _____       __    ____  ___
  / ___/__  __/ /_  / __ \/ _ \___  _________  ____
  \__ \/ / / / __ \/ /_/ / , _/ _ \/ ___/ __ \/ __ \
 ___/ / /_/ / /_/ / _, _/ /_/ /  __/ /__/ /_/ / / / /
/____/\__,_/_.___/_/ |_/_/  \\___/\___/\____/_/ /_/

  Passive + Active Subdomain Recon  |  for authorized testing only
""")


def query_crtsh(domain: str, timeout: int = 15) -> set:
    """
    Query crt.sh's JSON API for certificate transparency records.
    This is passive recon - it never sends a single packet to the target.
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        req = Request(url, headers={"User-Agent": "SubRecon/1.0 (educational tool)"})
        with urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="ignore")
            if not raw.strip():
                return subdomains
            data = json.loads(raw)
    except (URLError, json.JSONDecodeError, socket.timeout) as e:
        print(f"  [!] crt.sh query failed: {e}", file=sys.stderr)
        return subdomains

    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            line = line.strip().lower()
            if line and not line.startswith("*."):
                subdomains.add(line)
            elif line.startswith("*."):
                subdomains.add(line[2:])  # strip wildcard prefix

    # Filter out anything that isn't actually a subdomain of our target
    subdomains = {s for s in subdomains if s.endswith(domain)}
    return subdomains


def resolve_subdomain(subdomain: str) -> tuple:
    """Try to resolve a single subdomain. Returns (subdomain, ip_or_None)."""
    try:
        ip = socket.gethostbyname(subdomain)
        return (subdomain, ip)
    except (socket.gaierror, socket.timeout):
        return (subdomain, None)


def brute_force_dns(domain: str, wordlist_path: str, max_workers: int = 25) -> dict:
    """
    Active DNS brute-force using a wordlist. Resolves candidate.domain
    for every line in the wordlist, concurrently.
    """
    found = {}

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"  [!] Wordlist not found: {wordlist_path}", file=sys.stderr)
        return found

    candidates = [f"{word}.{domain}" for word in words]
    total = len(candidates)
    print(f"  [*] Brute-forcing {total} candidate subdomains "
          f"(concurrency={max_workers})...")

    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve_subdomain, c): c for c in candidates}
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            subdomain, ip = future.result()
            if ip:
                found[subdomain] = ip
                print(f"      [+] {subdomain:<40} -> {ip}")
            if completed % 100 == 0:
                print(f"      ... {completed}/{total} checked", file=sys.stderr)

    return found


def run_recon(domain: str, wordlist: str = None, max_workers: int = 25,
              passive_only: bool = False) -> ReconResult:
    start = time.time()
    result = ReconResult(domain=domain)

    print(f"[*] Target: {domain}")
    print(f"[*] Mode: {'passive only' if passive_only else 'passive + active'}\n")

    print("[*] Phase 1: Querying certificate transparency logs (crt.sh)...")
    result.passive_subdomains = query_crtsh(domain)
    print(f"    Found {len(result.passive_subdomains)} unique names via CT logs\n")

    if not passive_only and wordlist:
        print("[*] Phase 2: Active DNS brute-force...")
        result.active_subdomains = brute_force_dns(domain, wordlist, max_workers)
        print(f"    Resolved {len(result.active_subdomains)} live subdomains\n")
    elif not passive_only:
        print("[*] Phase 2: Skipped (no wordlist provided, use --wordlist)\n")

    result.duration_seconds = time.time() - start
    return result


def print_summary(result: ReconResult):
    all_found = set(result.passive_subdomains) | set(result.active_subdomains.keys())
    print("=" * 60)
    print(f"SUMMARY for {result.domain}")
    print("=" * 60)
    print(f"Total unique subdomains discovered : {len(all_found)}")
    print(f"  - From cert transparency (passive): {len(result.passive_subdomains)}")
    print(f"  - From DNS brute-force (active)    : {len(result.active_subdomains)}")
    print(f"Time elapsed                        : {result.duration_seconds:.1f}s")
    print("=" * 60)


def save_report(result: ReconResult, output_path: str):
    all_subdomains = sorted(set(result.passive_subdomains) | set(result.active_subdomains.keys()))
    report = {
        "domain": result.domain,
        "duration_seconds": round(result.duration_seconds, 2),
        "total_unique": len(all_subdomains),
        "passive_count": len(result.passive_subdomains),
        "active_count": len(result.active_subdomains),
        "subdomains": [
            {"name": s, "ip": result.active_subdomains.get(s, "unresolved/passive-only")}
            for s in all_subdomains
        ],
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Full report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Passive + active subdomain reconnaissance tool. "
                     "ONLY use active mode against domains you're authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for DNS brute-force")
    parser.add_argument("-o", "--output", default="recon_report.json",
                         help="Output JSON report path (default: recon_report.json)")
    parser.add_argument("--passive-only", action="store_true",
                         help="Only run passive cert-transparency lookup, skip DNS brute-force")
    parser.add_argument("--threads", type=int, default=25,
                         help="Concurrent DNS resolution threads (default: 25)")
    parser.add_argument("-y", "--yes", action="store_true",
                         help="Skip the authorization confirmation prompt")
    args = parser.parse_args()

    banner()

    if not args.passive_only and not args.yes:
        confirm = input(
            f"You are about to actively probe DNS for '{args.domain}'.\n"
            f"Type 'yes' to confirm you are authorized to test this domain: "
        )
        if confirm.strip().lower() != "yes":
            print("Aborting. Authorization not confirmed.")
            sys.exit(1)

    result = run_recon(
        domain=args.domain,
        wordlist=args.wordlist,
        max_workers=args.threads,
        passive_only=args.passive_only,
    )
    print_summary(result)
    save_report(result, args.output)


if __name__ == "__main__":
    main()
