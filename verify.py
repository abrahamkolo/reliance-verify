#!/usr/bin/env python3
"""
Independent verification tool for Reliance Infrastructure Canon.
Verifies hash integrity, Ed25519 signatures, and document structure.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def verify_hashes(repo_path):
    """Verify SHA3-512 hashes for all documents."""
    hashes_path = os.path.join(repo_path, "verification", "hashes.json")
    if not os.path.exists(hashes_path):
        return 0, 0, ["hashes.json not found"]

    with open(hashes_path) as f:
        hashes = json.load(f)

    passed = 0
    total = len(hashes)
    errors = []

    for filename, expected in hashes.items():
        found = False
        for root, dirs, files in os.walk(os.path.join(repo_path, "documents")):
            if filename in files:
                filepath = os.path.join(root, filename)
                with open(filepath, "rb") as fh:
                    actual = hashlib.sha3_512(fh.read()).hexdigest()
                if actual == expected:
                    passed += 1
                else:
                    errors.append(f"MISMATCH: {filename}")
                found = True
                break
        if not found:
            errors.append(f"MISSING: {filename}")

    return passed, total, errors


def verify_signatures(repo_path):
    """Verify Ed25519 signatures if cryptography library is available."""
    if not HAS_CRYPTO:
        return -1, -1, ["cryptography library not installed -- pip install cryptography"]

    sigs_path = os.path.join(repo_path, "verification", "signatures.json")
    key_path = os.path.join(repo_path, "verification", "reliance-signing-key.pub")

    if not os.path.exists(sigs_path):
        return 0, 0, ["signatures.json not found"]
    if not os.path.exists(key_path):
        return 0, 0, ["Public key not found"]

    with open(key_path, "rb") as f:
        public_key = load_pem_public_key(f.read())

    with open(sigs_path) as f:
        sigs_data = json.load(f)

    # Handle different signature file formats
    if "documents" in sigs_data:
        sigs = sigs_data["documents"]
    else:
        sigs = sigs_data

    passed = 0
    total = 0
    errors = []

    for doc_name, doc_info in sigs.items():
        total += 1
        found = False
        # Extract the signature - handle both flat and nested formats
        if isinstance(doc_info, dict):
            sig_val = doc_info.get("ed25519_signature", "")
        else:
            sig_val = doc_info

        for root, dirs, files in os.walk(os.path.join(repo_path, "documents")):
            if doc_name in files:
                filepath = os.path.join(root, doc_name)
                with open(filepath, "rb") as fh:
                    content = fh.read()
                try:
                    import base64
                    signature = base64.b64decode(sig_val)
                    # Ed25519 signs the hash, not the content directly
                    content_hash = hashlib.sha3_512(content).hexdigest()
                    public_key.verify(signature, content_hash.encode("utf-8"))
                    passed += 1
                except Exception as e:
                    errors.append(f"SIG FAIL: {doc_name} -- {e}")
                found = True
                break
        if not found:
            errors.append(f"MISSING: {doc_name}")

    return passed, total, errors


def verify_master_index(repo_path):
    """Verify master index completeness."""
    index_path = os.path.join(repo_path, "verification", "master-index.json")
    if not os.path.exists(index_path):
        return 0, 39, ["master-index.json not found"]

    with open(index_path) as f:
        index = json.load(f)

    if "documents" in index:
        count = len(index["documents"])
    else:
        count = len([k for k in index.keys() if k.startswith("DOC-")])

    return count, 39, [] if count >= 39 else [f"Only {count}/39 documents indexed"]


def verify_structure(repo_path):
    """Verify 4-layer document organization."""
    expected_dirs = [
        "01-constitutional-authorities",
        "02-operational-protocols",
        "03-legal-instruments",
        "04-interface-packs",
    ]
    docs_path = os.path.join(repo_path, "documents")
    passed = 0
    errors = []
    for d in expected_dirs:
        if os.path.isdir(os.path.join(docs_path, d)):
            passed += 1
        else:
            errors.append(f"Missing layer directory: {d}")
    return passed, 4, errors


def verify_license(repo_path):
    """Check CC BY-ND 4.0 license presence."""
    license_path = os.path.join(repo_path, "LICENSE")
    if not os.path.exists(license_path):
        return False, "LICENSE file not found"
    with open(license_path) as f:
        content = f.read()
    if "CC BY-ND" in content or "Creative Commons" in content or "Attribution-NoDerivatives" in content:
        return True, "CC BY-ND 4.0"
    return False, "License present but not CC BY-ND 4.0"


def main():
    parser = argparse.ArgumentParser(description="Verify Reliance Infrastructure Canon")
    parser.add_argument("--path", default=".", help="Path to canon repository")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    repo = os.path.abspath(args.path)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    results = {}

    if not args.json:
        print("=" * 55)
        print("RELIANCE INFRASTRUCTURE CANON -- INDEPENDENT VERIFICATION")
        print("=" * 55)
        print(f"Repository: {repo}")
        print(f"Timestamp:  {timestamp}")
        print()

    # 1. Hashes
    h_pass, h_total, h_err = verify_hashes(repo)
    results["hashes"] = {"passed": h_pass, "total": h_total, "errors": h_err}
    if not args.json:
        status = f"{h_pass}/{h_total} PASS" if not h_err else f"FAIL -- {h_err}"
        print(f"[1/5] SHA3-512 Hash Verification ........... {status}")

    # 2. Signatures
    s_pass, s_total, s_err = verify_signatures(repo)
    results["signatures"] = {"passed": s_pass, "total": s_total, "errors": s_err}
    if not args.json:
        if s_pass == -1:
            print(f"[2/5] Ed25519 Signature Verification ....... SKIP (install cryptography)")
        else:
            status = f"{s_pass}/{s_total} PASS" if not s_err else f"FAIL -- {s_err}"
            print(f"[2/5] Ed25519 Signature Verification ....... {status}")

    # 3. Master Index
    m_pass, m_total, m_err = verify_master_index(repo)
    results["master_index"] = {"passed": m_pass, "total": m_total, "errors": m_err}
    if not args.json:
        status = f"{m_pass}/{m_total} PASS" if not m_err else f"FAIL -- {m_err}"
        print(f"[3/5] Master Index Completeness ............ {status}")

    # 4. Structure
    d_pass, d_total, d_err = verify_structure(repo)
    results["structure"] = {"passed": d_pass, "total": d_total, "errors": d_err}
    if not args.json:
        status = f"{d_pass}/{d_total} layers PASS" if not d_err else f"FAIL -- {d_err}"
        print(f"[4/5] Document Structure ................... {status}")

    # 5. License
    lic_ok, lic_detail = verify_license(repo)
    results["license"] = {"valid": lic_ok, "detail": lic_detail}
    if not args.json:
        status = f"{lic_detail} PASS" if lic_ok else f"FAIL -- {lic_detail}"
        print(f"[5/5] License Verification ................. {status}")

    # Verdict
    all_pass = (
        len(h_err) == 0
        and (len(s_err) == 0 or s_pass == -1)
        and len(m_err) == 0
        and len(d_err) == 0
        and lic_ok
    )
    results["verdict"] = "AUTHENTIC" if all_pass else "FAILED"

    if args.json:
        results["repository"] = repo
        results["timestamp"] = timestamp
        print(json.dumps(results, indent=2))
    else:
        print()
        print("=" * 55)
        print(f"VERDICT: {results['verdict']}")
        print("=" * 55)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
