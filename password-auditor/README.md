# PassAudit

a password strength and policy auditing tool
for ethical hacking / security portfolio work.

## what it does

analyzes passwords (one at a time or in bulk from a file) against common
real-world weaknesses:

- length and estimated entropy (NIST-style heuristic, not cryptographic)
- character diversity (upper/lower/digit/symbol)
- presence in a list of commonly breached passwords
- keyboard walk patterns (`qwerty`, `asdf`, etc.)
- sequential characters (`abc`, `123`)
- repeated characters (`aaa`, `111`)

it outputs a 0–100 score, a verdict (strong / moderate / weak / very weak),
and a list of specific issues - plus an optional JSON report for handoff.

## what this is *not*

this is **not a password cracker**. it doesn't attempt to guess passwords or brute-force any live system. it's a static analysis tool.
think of it as a linter for password strength, useful for:

- reviewing your org's password policy effectiveness
- security awareness training material
- auditing a list of sample/test passwords during a security review

## usage

```bash
# check a single password (output is masked by default)
python3 passaudit.py -p "MyPassword123"

# audit a whole file (one password per line)
python3 passaudit.py -f passwords.txt

# save a JSON report
python3 passaudit.py -f passwords.txt -o report.json

# show raw (unmasked) passwords in output - only do this locally / safely
python3 passaudit.py -f passwords.txt --show-raw
```

## example output

```
Password: M*************!
  Verdict       : Strong  (score: 90/100)
  Length        : 15
  Est. entropy  : 98.5 bits
  Char types    : lower upper digit symbol
  Issues: none found
```

## design notes (useful talking points for interviews)

- **masking by default**: raw passwords are never printed unless you pass
  `--show-raw` explicitly - a small but meaningful default-safe design choice.
- **entropy estimate**: uses pool-size × length as a simple, explainable
  heuristic (not perfect, but transparent - good for explaining trade-offs
  if asked about it).
- **extensible common-password list**: ships with a small built-in list;
  designed so you can swap in a real breached-password corpus (e.g. a local
  copy of a known breach compilation) for more rigorous audits.

## possible extensions (good "v2" ideas)

- load the common-password list from an external file instead of hardcoding it
- add a check against k-anonymity APIs like Have I Been Pwned's Pwned Passwords
  API (which is designed for safe, privacy-preserving online lookups)
- add a `--policy` mode that checks passwords against a configurable policy
  (e.g. "must be 14+ chars, no dictionary words") and reports pass/fail
- add support for zxcvbn-style pattern matching for even better estimates

## requirements

- python 3.8+
- no third-party packages — uses only the standard library
