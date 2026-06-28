#!/usr/bin/env python3
"""
PassAudit - Password Policy & Strength Auditor
=================================================

A tool for security audits that evaluates password lists or policies
against common weaknesses: low entropy, dictionary words, predictable
patterns, and known-breached passwords (via local list, not online
lookups - see note below).

WHAT THIS TOOL IS FOR:
  - Auditing your organization's password policy
  - Checking a list of (already-known-to-you) passwords for weaknesses,
    e.g. during a security review where users provided sample passwords
  - Educational demonstration of what makes passwords weak/strong
  - Generating a report you can hand to stakeholders

WHAT THIS TOOL IS NOT FOR:
  - This is NOT a password cracker. It doesn't attempt to guess or
    crack hashes, and it doesn't brute-force anything.
  - It does not perform online lookups against live accounts.

Author: Asser Nashaat
License: MIT
"""

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


# A small built-in list of extremely common passwords for pattern matching.
# For real audits, swap in a proper breached-password corpus (e.g. a local
# copy of "rockyou.txt" or Have I Been Pwned's downloadable hash list -
# used OFFLINE, never as an online API call against live credentials).
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "iloveyou", "sunshine",
    "princess", "football", "baseball", "trustno1", "qwerty123",
    "1q2w3e4r", "passw0rd", "starwars", "shadow", "michael", "superman",
}

KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "1qaz2wsx", "qwertyuiop",
]


@dataclass
class PasswordAnalysis:
    password: str
    length: int = 0
    entropy_bits: float = 0.0
    has_lower: bool = False
    has_upper: bool = False
    has_digit: bool = False
    has_symbol: bool = False
    is_common: bool = False
    has_keyboard_pattern: bool = False
    has_sequential_chars: bool = False
    has_repeated_chars: bool = False
    score: int = 0  # 0-100
    verdict: str = ""
    issues: list = field(default_factory=list)


def calculate_entropy(password: str) -> float:
    """
    Estimate Shannon entropy based on character pool size and length.
    This is a simplified model (NIST-style), not cryptographic entropy -
    it's a useful heuristic for comparing relative password strength.
    """
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33  # rough estimate of common symbol set

    if pool == 0 or len(password) == 0:
        return 0.0

    return len(password) * math.log2(pool)


def has_sequential_chars(password: str, run_length: int = 3) -> bool:
    """Detect sequences like 'abc', '123', 'xyz' of a given run length."""
    lower = password.lower()
    for i in range(len(lower) - run_length + 1):
        chunk = lower[i:i + run_length]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return True
    return False


def has_repeated_chars(password: str, repeat_threshold: int = 3) -> bool:
    """Detect repeated characters like 'aaa' or '111'."""
    for i in range(len(password) - repeat_threshold + 1):
        chunk = password[i:i + repeat_threshold]
        if len(set(chunk)) == 1:
            return True
    return False


def has_keyboard_pattern(password: str) -> bool:
    lower = password.lower()
    return any(pattern in lower for pattern in KEYBOARD_PATTERNS)


def analyze_password(password: str) -> PasswordAnalysis:
    analysis = PasswordAnalysis(password=password)
    analysis.length = len(password)
    analysis.entropy_bits = calculate_entropy(password)
    analysis.has_lower = bool(re.search(r"[a-z]", password))
    analysis.has_upper = bool(re.search(r"[A-Z]", password))
    analysis.has_digit = bool(re.search(r"[0-9]", password))
    analysis.has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    analysis.is_common = password.lower() in COMMON_PASSWORDS
    analysis.has_keyboard_pattern = has_keyboard_pattern(password)
    analysis.has_sequential_chars = has_sequential_chars(password)
    analysis.has_repeated_chars = has_repeated_chars(password)

    score = 0
    issues = []

    # Length scoring (most impactful factor)
    if analysis.length >= 16:
        score += 35
    elif analysis.length >= 12:
        score += 25
    elif analysis.length >= 8:
        score += 10
        issues.append("Consider using 12+ characters for better security")
    else:
        issues.append(f"Too short ({analysis.length} chars) - use at least 12")

    # Character diversity
    diversity = sum([analysis.has_lower, analysis.has_upper,
                      analysis.has_digit, analysis.has_symbol])
    score += diversity * 10
    if diversity < 3:
        issues.append("Low character diversity - mix upper/lower/digits/symbols")

    # Entropy bonus
    if analysis.entropy_bits >= 60:
        score += 25
    elif analysis.entropy_bits >= 40:
        score += 15
    elif analysis.entropy_bits >= 28:
        score += 5

    # Penalties
    if analysis.is_common:
        score = min(score, 5)
        issues.append("This is one of the most commonly breached passwords")
    if analysis.has_keyboard_pattern:
        score -= 15
        issues.append("Contains a recognizable keyboard pattern (e.g. 'qwerty')")
    if analysis.has_sequential_chars:
        score -= 10
        issues.append("Contains sequential characters (e.g. 'abc', '123')")
    if analysis.has_repeated_chars:
        score -= 10
        issues.append("Contains repeated characters (e.g. 'aaa', '111')")

    score = max(0, min(100, score))
    analysis.score = score
    analysis.issues = issues

    if score >= 80:
        analysis.verdict = "Strong"
    elif score >= 60:
        analysis.verdict = "Moderate"
    elif score >= 35:
        analysis.verdict = "Weak"
    else:
        analysis.verdict = "Very Weak"

    return analysis


def mask_password(password: str) -> str:
    """For reports, avoid printing raw passwords - show a masked version."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def print_single_report(analysis: PasswordAnalysis, show_raw: bool):
    label = analysis.password if show_raw else mask_password(analysis.password)
    print(f"\nPassword: {label}")
    print(f"  Verdict       : {analysis.verdict}  (score: {analysis.score}/100)")
    print(f"  Length        : {analysis.length}")
    print(f"  Est. entropy  : {analysis.entropy_bits:.1f} bits")
    char_types = (
        f"{'lower ' if analysis.has_lower else ''}"
        f"{'upper ' if analysis.has_upper else ''}"
        f"{'digit ' if analysis.has_digit else ''}"
        f"{'symbol' if analysis.has_symbol else ''}"
    ).strip() or "none"
    print(f"  Char types    : {char_types}")
    if analysis.issues:
        print("  Issues:")
        for issue in analysis.issues:
            print(f"    - {issue}")
    else:
        print("  Issues: none found")


def audit_file(path: str, show_raw: bool) -> list:
    results = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.strip()
            if pw:
                results.append(analyze_password(pw))
    return results


def print_batch_summary(results: list):
    total = len(results)
    if total == 0:
        print("No passwords to analyze.")
        return

    verdict_counts = {"Strong": 0, "Moderate": 0, "Weak": 0, "Very Weak": 0}
    for r in results:
        verdict_counts[r.verdict] += 1

    avg_score = sum(r.score for r in results) / total
    common_count = sum(1 for r in results if r.is_common)

    print("\n" + "=" * 55)
    print(f"BATCH AUDIT SUMMARY ({total} passwords analyzed)")
    print("=" * 55)
    print(f"Average score          : {avg_score:.1f}/100")
    for verdict, count in verdict_counts.items():
        pct = (count / total) * 100
        print(f"  {verdict:<10}: {count:>4}  ({pct:.1f}%)")
    print(f"Found in common list    : {common_count} ({(common_count/total)*100:.1f}%)")
    print("=" * 55)


def save_json_report(results: list, output_path: str, show_raw: bool):
    report = []
    for r in results:
        report.append({
            "password": r.password if show_raw else mask_password(r.password),
            "score": r.score,
            "verdict": r.verdict,
            "length": r.length,
            "entropy_bits": round(r.entropy_bits, 2),
            "is_common": r.is_common,
            "issues": r.issues,
        })
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] Full report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Audit password strength against common weaknesses. "
                     "Not a cracker - does not guess or brute-force anything.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--password", help="Analyze a single password")
    group.add_argument("-f", "--file", help="Path to a file with one password per line")

    parser.add_argument("-o", "--output", help="Save JSON report to this path")
    parser.add_argument("--show-raw", action="store_true",
                         help="Show raw passwords in output instead of masking them "
                              "(use with caution - e.g. only on your own machine)")
    args = parser.parse_args()

    if args.password:
        analysis = analyze_password(args.password)
        print_single_report(analysis, show_raw=args.show_raw)
        if args.output:
            save_json_report([analysis], args.output, args.show_raw)

    elif args.file:
        if not Path(args.file).exists():
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        results = audit_file(args.file, show_raw=args.show_raw)
        for r in results:
            print_single_report(r, show_raw=args.show_raw)
        print_batch_summary(results)
        if args.output:
            save_json_report(results, args.output, args.show_raw)


if __name__ == "__main__":
    main()
