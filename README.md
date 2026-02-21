# reliance-verify

Independent verification tool for [Reliance Infrastructure Canon](https://github.com/abrahamkolo/reliance-infrastructure-canon) documents.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Verify Canon](https://github.com/abrahamkolo/reliance-verify/actions/workflows/verify.yml/badge.svg)](https://github.com/abrahamkolo/reliance-verify/actions/workflows/verify.yml)

## Quick Start

```bash
pip install -r requirements.txt
python verify.py --repo https://github.com/abrahamkolo/reliance-infrastructure-canon
```

## What It Checks

1. **SHA3-512 hash integrity** -- every document matches its registered hash
2. **Ed25519 signature verification** -- every signature validates against the public key
3. **Master index completeness** -- all 39 documents are indexed
4. **Document structure** -- 4-layer organization is intact
5. **License verification** -- CC BY-ND 4.0 is present

## Standalone Usage

Clone any Reliance Infrastructure Canon repository and point this tool at it:

```bash
git clone https://github.com/abrahamkolo/reliance-infrastructure-canon.git
python verify.py --path ./reliance-infrastructure-canon
```

## Output

```
=======================================================
RELIANCE INFRASTRUCTURE CANON -- INDEPENDENT VERIFICATION
=======================================================
Repository: ./reliance-infrastructure-canon
Timestamp:  2026-02-20T12:00:00Z

[1/5] SHA3-512 Hash Verification ........... 39/39 PASS
[2/5] Ed25519 Signature Verification ....... 39/39 PASS
[3/5] Master Index Completeness ............ 39/39 PASS
[4/5] Document Structure ................... 4/4 layers PASS
[5/5] License Verification ................. CC BY-ND 4.0 PASS

=======================================================
VERDICT: AUTHENTIC
=======================================================
```

## Why This Exists

Institutional-grade infrastructure requires independent verification. This tool allows any third party to verify the integrity and authenticity of the Reliance Infrastructure Canon without trusting the source repository's own scripts.

## Related

- [Reliance Infrastructure Canon](https://github.com/abrahamkolo/reliance-infrastructure-canon) -- the 39-document canonical stack
- [Governance Templates](https://github.com/abrahamkolo/governance-templates) -- reusable document templates

## License

MIT -- use freely for verification purposes.
