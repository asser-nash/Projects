# PassAudit

A password strength and policy auditing tool — built as a learning project
for ethical hacking / security portfolio work.

## What it does

Analyzes passwords (one at a time or in bulk from a file) against common
real-world weaknesses:

- Length and estimated entropy (NIST-style heuristic, not cryptographic)
- Character diversity (upper/lower/digit/symbol)
- Presence in a list of commonly breached passwords
- Keyboard walk patterns (`qwerty`, `asdf`, etc.)
- Sequential characters (`abc`, `123`)
- Repeated characters (`aaa`, `111`)

It outputs a 0–100 score, a verdict (Strong / Moderate / Weak / Very Weak),
and a list of specific issues — plus an optional JSON report for handoff.

## What this is *not*

This is **not a password cracker**. It doesn't attempt to guess passwords,
crack hashes, or brute-force any live system. It's a static analysis tool —
think of it as a linter for password strength, useful for:

- Reviewing your org's password policy effectiveness
- Security awareness training material
- Auditing a list of sample/test passwords during a security review

## Usage

```bash
# Check a single password (output is masked by default)
python3 passaudit.py -p "MyPassword123"

# Audit a whole file (one password per line)
python3 passaudit.py -f passwords.txt

# Save a JSON report
python3 passaudit.py -f passwords.txt -o report.json

# Show raw (unmasked) passwords in output - only do this locally / safely
python3 passaudit.py -f passwords.txt --show-raw
```

## Example output

```
Password: M*************!
  Verdict       : Strong  (score: 90/100)
  Length        : 15
  Est. entropy  : 98.5 bits
  Char types    : lower upper digit symbol
  Issues: none found
```

## Design notes (useful talking points for interviews)

- **Masking by default**: raw passwords are never printed unless you pass
  `--show-raw` explicitly — a small but meaningful default-safe design choice.
- **Entropy estimate**: uses pool-size × length as a simple, explainable
  heuristic (not perfect, but transparent — good for explaining trade-offs
  if asked about it).
- **Extensible common-password list**: ships with a small built-in list;
  designed so you can swap in a real breached-password corpus (e.g. a local
  copy of a known breach compilation) for more rigorous audits.

## Possible extensions (good "v2" ideas)

- Load the common-password list from an external file instead of hardcoding it
- Add a check against k-anonymity APIs like Have I Been Pwned's Pwned Passwords
  API (which is designed for safe, privacy-preserving online lookups)
- Add a `--policy` mode that checks passwords against a configurable policy
  (e.g. "must be 14+ chars, no dictionary words") and reports pass/fail
- Add support for zxcvbn-style pattern matching for even better estimates

## Requirements

- Python 3.8+
- No third-party packages — uses only the standard library
