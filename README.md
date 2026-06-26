# security tools

a growing collection of small tools I've built while learning offensive
security and ethical hacking. Each tool lives in its own folder with a
detailed README, usage instructions, and notes on ethical/legal use.

## tools

### [`subdomain-recon/`](./subdomain-recon)
[assive + active subdomain enumeration tool. combines certificate
transparency log lookups (crt.sh) with concurrent DNS brute-forcing to map
out a target's attack surface. built-in authorization prompt before running
any active scanning.

### [`password-auditor/`](./password-auditor)
password strength and policy auditor. Scores passwords against length,
entropy, character diversity, common-password lists, and predictable
patterns (keyboard walks, sequences, repeats).

## why I'm building this

i'm working toward a career in offensive security / penetration testing.
these tools are part of how i'm learning the fundamentals hands-on such as
reconnaissance techniques, scripting for security workflows, and thinking
through the ethical boundaries of the tooling itself.

## a note on ethical use

every tool in this repo is built for **authorized** security testing only —
your own systems, CTF environments, or engagements you have explicit
permission to test. each tool's README spells out the specifics, but the
short version: recon responsibly, get permission first, and don't point
anything active at a target you don't own or have a signed agreement to test.

## tech

python 3.8+, standard library only (no external dependencies to install).

## license

each tool is individually MIT licensed — see the `LICENSE` file inside its
folder.
