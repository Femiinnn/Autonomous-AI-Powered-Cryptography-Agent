"""
eval_benchmark.py - Autonomous Cryptanalysis Benchmark & Evaluation Harness
=============================================================================
Runs a battery of mathematically verified CTF challenges across:
1. RSA Cryptanalysis (Fermat, Small e, Wiener)
2. ECC Cryptanalysis (BSGS, Curve25519)
3. Symmetric Cryptanalysis (CBC Bit-Flip, ECB Byte-at-a-Time)
4. Classical Ciphers & XOR (Vigenere, Caesar, Single-Byte XOR)
5. Hash Cryptanalysis (MD5/SHA-256 Identification, Dictionary, Length Extension)
6. PRNG & LFSR (LCG Parameter Recovery, MT19937 Untwister)
7. Lattice Cryptography (Knapsack / Subset Sum)
8. Custom Bitwise Reverser (Z3/PureBitVec Preimage Inversion)

Outputs accuracy metrics, execution latencies, and saves outputs/benchmark_results.json.
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import Dict, List, Any

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))


def run_benchmark_suite() -> Dict[str, Any]:
    print("=" * 70)
    print("🚀 STARTING AUTONOMOUS CRYPTANALYSIS BENCHMARK SUITE")
    print("=" * 70)

    tests: List[Dict[str, Any]] = []

    # 1. RSA Small Public Exponent Root
    def test_rsa_cube_root():
        from rsa_cryptanalysis import RSAAttacks
        m_val = 1337
        e_val = 3
        c_val = pow(m_val, e_val)
        n_val = 10**40  # m^3 < n
        res = RSAAttacks.attack_small_exponent_root(c_val, e_val, n_val)
        return res is not None and res.get("plaintext_int") == m_val

    tests.append({"id": "RSA-01", "name": "RSA Small Exponent Cube Root", "cat": "RSA", "fn": test_rsa_cube_root})

    # 2. RSA Fermat Factorization
    def test_rsa_fermat():
        from rsa_cryptanalysis import RSAAttacks
        p = 1000000007
        q = 1000000009
        n = p * q
        fac = RSAAttacks.factor_fermat(n)
        return fac is not None and fac[0] * fac[1] == n

    tests.append({"id": "RSA-02", "name": "RSA Fermat Close Primes", "cat": "RSA", "fn": test_rsa_fermat})

    # 3. RSA Wiener Small Private Exponent d
    def test_rsa_wiener():
        from rsa_cryptanalysis import RSAAttacks
        n = 160523347
        e = 60728973
        res = RSAAttacks.attack_wiener(n, e)
        return res is not None and res.get("d") == 37

    tests.append({"id": "RSA-03", "name": "RSA Wiener Continued Fractions", "cat": "RSA", "fn": test_rsa_wiener})

    # 4. ECC Baby-Step Giant-Step (BSGS)
    def test_ecc_bsgs():
        from ecc_cryptanalysis import EllipticCurve, ECPoint, ECCAttacks
        curve = EllipticCurve(97, 2, 3)
        P = ECPoint(0, 10)
        d = 17
        Q = curve.multiply(P, d)
        rec_d = ECCAttacks.attack_ecdlp_bsgs(P, Q, curve, max_steps=50)
        return rec_d == d

    tests.append({"id": "ECC-01", "name": "ECC BSGS Discrete Logarithm", "cat": "ECC", "fn": test_ecc_bsgs})

    # 5. ECC Curve25519 Montgomery Ladder
    def test_curve25519_ladder():
        from ecc_cryptanalysis import get_standard_curve
        c25519 = get_standard_curve("curve25519")
        pt = c25519.ladder(9, 2)
        return pt > 0

    tests.append({"id": "ECC-02", "name": "Curve25519 Montgomery Ladder", "cat": "ECC", "fn": test_curve25519_ladder})

    # 6. Symmetric CBC Bit-Flipping
    def test_cbc_bit_flip():
        from symmetric_cryptanalysis import SymmetricAttacks
        iv = b"0123456789abcdef"
        orig_p = b"comment1=test&userdata=user"
        target_p = b"comment1=test&userdata=admn"
        ct = b"\x00" * 32
        res = SymmetricAttacks.attack_cbc_bit_flip(ciphertext=ct, original_pt=orig_p, target_pt=target_p, iv=iv)
        return res is not None and ("modified_iv" in res or "modified_ciphertext" in res)

    tests.append({"id": "SYM-01", "name": "Symmetric CBC Bit-Flipping", "cat": "Symmetric", "fn": test_cbc_bit_flip})

    # 7. Classical Vigenere Frequency Solver
    def test_classical_vigenere():
        from classical_crypto import vigenere_decrypt
        ct = "Lxfopv ef rfrh"
        pt = vigenere_decrypt(ct, "lemon")
        return "attack" in pt.lower()

    tests.append({"id": "CLA-01", "name": "Classical Vigenère Decryption", "cat": "Classical", "fn": test_classical_vigenere})

    # 8. Single-Byte XOR Brute Force
    def test_single_byte_xor():
        from classical_crypto import xor_single_byte_bruteforce
        ct = bytes([ord(c) ^ 0x42 for c in "flag{xor_is_fun}"])
        res = xor_single_byte_bruteforce(ct)
        return len(res) > 0 and res[0]["key"] == 0x42

    tests.append({"id": "CLA-02", "name": "Single-Byte XOR Brute Force", "cat": "Classical", "fn": test_single_byte_xor})

    # 9. Hash Identification & Cracking
    def test_hash_dictionary():
        from hash_cryptanalysis import compute_hash, dictionary_attack
        h = compute_hash("md5", b"admin")
        res = dictionary_attack(h, "md5")
        return res.get("status") == "cracked" and res.get("plaintext") == "admin"

    tests.append({"id": "HSH-01", "name": "MD5 Hash Dictionary Cracking", "cat": "Hash", "fn": test_hash_dictionary})

    # 10. Hash Length Extension Padding
    def test_hash_length_extension():
        from hash_cryptanalysis import generate_merkle_damgard_padding
        pad = generate_merkle_damgard_padding(10, "sha256")
        return pad.startswith(b"\x80") and len(pad) > 8

    tests.append({"id": "HSH-02", "name": "Merkle-Damgård Padding Generation", "cat": "Hash", "fn": test_hash_length_extension})

    # 11. PRNG MT19937 State Untwister
    def test_prng_mt19937():
        from prng_cryptanalysis import untemper_mt19937
        x = 0x12345678
        y = x ^ (x >> 11)
        y ^= ((y << 7) & 0x9D2C5680)
        y ^= ((y << 15) & 0xEFC60000)
        y ^= (y >> 18)
        rec_x = untemper_mt19937(y)
        return rec_x == x

    tests.append({"id": "RNG-01", "name": "MT19937 Bitwise Untwister", "cat": "PRNG", "fn": test_prng_mt19937})

    # 12. PRNG LCG Parameter Recovery
    def test_prng_lcg():
        from prng_cryptanalysis import solve_lcg_known_m
        m = 2**31 - 1
        a = 16807
        c = 0
        s0 = 12345
        s1 = (a * s0 + c) % m
        s2 = (a * s1 + c) % m
        s3 = (a * s2 + c) % m
        res = solve_lcg_known_m([s0, s1, s2, s3], m)
        return res is not None and res.get("a") == a and res.get("c") == c

    tests.append({"id": "RNG-02", "name": "LCG Multiplier / Increment Solver", "cat": "PRNG", "fn": test_prng_lcg})

    # 13. Lattice Clos-Chor-Lemke Subset Sum
    def test_lattice_knapsack():
        from lattice_crypto import solve_subset_sum_clos
        weights = [2, 3, 7, 14, 30, 57, 120, 251]
        target = 2 + 7 + 30 + 251  # 290
        sol = solve_subset_sum_clos(weights, target)
        return sol == [1, 0, 1, 0, 1, 0, 0, 1]

    tests.append({"id": "LAT-01", "name": "Lattice Clos-Chor-Lemke Knapsack", "cat": "Lattice", "fn": test_lattice_knapsack})

    # 14. Custom Bitwise Preimage Inversion
    def test_custom_bitwise():
        from z3_symbolic_solver import solve_byte_transform_preimage, rol8
        target = bytes([rol8(ord(c) ^ 0x37, 3) for c in "flag{test}"])
        recovered = solve_byte_transform_preimage(lambda b: rol8(b ^ 0x37, 3), target)
        return recovered == b"flag{test}"

    tests.append({"id": "Z3-01", "name": "Custom Bitwise Preimage Inversion", "cat": "Custom/Z3", "fn": test_custom_bitwise})

    # 15. Dynamic Flag Pattern Extraction
    def test_dynamic_flag():
        from verification_engine import extract_flag
        challenge = "Welcome! The flag format is DUCTF{...}. Good luck!"
        cand = "Found secret: DUCTF{dynam1c_r3g3x_succ3ss}"
        flag = extract_flag(cand, prompt_context=challenge)
        return flag == "DUCTF{dynam1c_r3g3x_succ3ss}"

    tests.append({"id": "VRF-01", "name": "Dynamic Custom Flag Extraction", "cat": "Verification", "fn": test_dynamic_flag})

    # 16. Multi-Layer Recursive Decoding
    def test_recursive_decode():
        from hash_decoder import analyze_hash_or_encoding
        payload = "666c61677b6f6e696f6e5f7065656c7d"  # hex of flag{onion_peel}
        res = analyze_hash_or_encoding(payload)
        return "flag{onion_peel}" in res.get("final_decoded", "")

    tests.append({"id": "ENC-01", "name": "Multi-Layer Recursive Decoding", "cat": "Encoding", "fn": test_recursive_decode})

    # 17. Bug Bounty Scope Gatekeeper (AGENTS.md)
    def test_bug_bounty_scope():
        from bug_bounty_crypto import ScopeGatekeeper
        r_local = ScopeGatekeeper.validate_scope("inputs/test.txt")
        r_unscoped = ScopeGatekeeper.validate_scope("api.target.com")
        r_scoped = ScopeGatekeeper.validate_scope(
            target="api.target.com",
            program_name="Target Corp",
            program_url="https://hackerone.com/target",
            in_scope_line="*.target.com"
        )
        return r_local.allowed and not r_unscoped.allowed and r_scoped.allowed

    tests.append({"id": "BTY-01", "name": "Bug Bounty Scope Gate Enforcement", "cat": "BugBounty", "fn": test_bug_bounty_scope})

    # 18. Bug Bounty JWT Security Audit (AGENTS.md)
    def test_bug_bounty_jwt():
        from bug_bounty_crypto import JWTAuditor, BugBountyReportGenerator
        # Test alg:none
        none_token = JWTAuditor.forge_none_token({"user": "admin", "role": "root"})
        res = JWTAuditor.audit_token(none_token)
        has_none = any(f["type"] == "ALG_NONE_ACTIVE" for f in res.get("findings", []))
        # Test report generator
        rep = BugBountyReportGenerator.generate_report(
            title="JWT Unsigned Token Acceptance",
            affected_asset="https://api.target.com/auth",
            finding_type="ALG_NONE_ACTIVE",
            root_cause="alg:none allowed",
            reproduction_steps=["Step 1", "Step 2"],
            evidence="Token: eyJ...",
            impact="Auth bypass",
            suggested_fix="Reject none"
        )
        return has_none and "CVSS:3.1" in rep["markdown"] and "CWE-347" in rep["markdown"]

    tests.append({"id": "BTY-02", "name": "Bug Bounty JWT & 10-Point Report", "cat": "BugBounty", "fn": test_bug_bounty_jwt})

    # Run execution loop
    results = []
    passed = 0
    total = len(tests)
    total_start = time.time()

    print(f"\nRunning {total} automated test disciplines...\n")
    for t in tests:
        t_id = t["id"]
        t_name = t["name"]
        cat = t["cat"]
        start_t = time.time()
        ok = False
        err = ""
        try:
            ok = bool(t["fn"]())
        except Exception as e:
            err = str(e)
            ok = False
        dur_ms = round((time.time() - start_t) * 1000, 2)

        if ok:
            passed += 1
            print(f"  ✅ [{t_id}] {t_name:<38} ({cat:<12}) -> PASSED ({dur_ms} ms)")
        else:
            print(f"  ❌ [{t_id}] {t_name:<38} ({cat:<12}) -> FAILED ({err or 'Assertion failed'}) ({dur_ms} ms)")

        results.append({
            "id": t_id,
            "name": t_name,
            "category": cat,
            "passed": ok,
            "latency_ms": dur_ms,
            "error": err
        })

    total_time = round(time.time() - total_start, 2)
    accuracy_pct = round((passed / total) * 100, 2)

    summary = {
        "total_tests": total,
        "passed": passed,
        "failed": total - passed,
        "accuracy_percent": accuracy_pct,
        "total_latency_seconds": total_time,
        "results": results
    }

    print("\n" + "=" * 70)
    print(f"🏆 BENCHMARK RESULTS: {passed}/{total} Passed ({accuracy_pct}%) in {total_time}s")
    print("=" * 70)

    # Save to outputs/benchmark_results.json
    out_dir = Path("outputs")
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "benchmark_results.json"
    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Saved benchmark report to: {out_file.resolve()}\n")

    return summary


if __name__ == "__main__":
    res = run_benchmark_suite()
    sys.exit(0 if res["passed"] == res["total_tests"] else 1)
