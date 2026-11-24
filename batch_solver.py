"""
Parallel Multi-Challenge CTF Batch Solver (batch_solver.py)
==========================================================
Enables high-throughput automated cryptanalysis during competition sprints:
  - Ingests batches of challenges simultaneously (JSON lists, text files, directories).
  - Uses concurrent thread workers to execute fast speculative attacks (encoding layers,
    classical substitution, weak RSA, MT19937, hash cracking, symmetric bit flips).
  - Produces a prioritized CTF Triage Leaderboard ranking challenges from easiest
    (instantly solved) to hardest, allowing competition teams to capture rapid points.
"""

import os
import re
import time
import uuid
import concurrent.futures
from typing import Dict, Any, List, Optional
from pathlib import Path


class BatchSolver:
    """
    Coordinates concurrent execution of speculative cryptanalysis across multiple challenges.
    """

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.batch_id = str(uuid.uuid4())[:8]

    def solve_single(self, challenge_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes fast speculative analysis on a single challenge item.
        """
        cid = challenge_item.get("id", str(uuid.uuid4())[:6])
        name = challenge_item.get("name", f"Challenge-{cid}")
        text = challenge_item.get("text", "")
        start_t = time.time()

        res_entry = {
            "id": cid,
            "name": name,
            "status": "UNSOLVED",
            "category": "Unknown",
            "vulnerability": "None",
            "flag": None,
            "latency_ms": 0.0,
            "extracted_parameters": {},
            "confidence": "LOW"
        }

        if not text.strip():
            res_entry["latency_ms"] = round((time.time() - start_t) * 1000, 2)
            return res_entry

        try:
            # 1. Parameter extraction & hypothesis ranking
            from attack_selector import extract_parameters, analyze_ciphertext_characteristics, rank_attack_strategies
            params = extract_parameters(text)
            charac = analyze_ciphertext_characteristics(text)
            ranked = rank_attack_strategies(params, charac, text)
            res_entry["extracted_parameters"] = params

            if ranked:
                top = ranked[0]
                res_entry["category"] = top.get("category", "General")
                res_entry["vulnerability"] = top.get("attack", "Unknown Attack")
                res_entry["confidence"] = "HIGH" if top.get("probability", 0) >= 0.75 else "MEDIUM"

            # 2. Fast Encoding & Hash Decoding
            clean_str = text.strip()
            if len(clean_str) in (32, 40, 64) and re.match(r'^[0-9a-fA-F]+$', clean_str):
                from hash_cryptanalysis import dictionary_attack, identify_hash_type
                cand_types = identify_hash_type(clean_str)
                algo = cand_types[0]["algo"] if cand_types else ("md5" if len(clean_str) == 32 else "sha256")
                h_res = dictionary_attack(clean_str, algo)
                if h_res.get("status") == "cracked":
                    res_entry["status"] = "SOLVED"
                    res_entry["category"] = "Hash Cryptanalysis"
                    res_entry["vulnerability"] = f"Dictionary Recovery ({algo})"
                    res_entry["flag"] = h_res.get("plaintext")
                    res_entry["latency_ms"] = round((time.time() - start_t) * 1000, 2)
                    return res_entry

            from hash_decoder import analyze_hash_or_encoding
            dec_res = analyze_hash_or_encoding(text)
            if dec_res.get("is_hash"):
                from hash_cryptanalysis import dictionary_attack
                chash = dec_res.get("final_decoded") or text.strip()
                h_res = dictionary_attack(chash, "md5" if len(chash) == 32 else "sha256")
                if h_res.get("status") == "cracked":
                    res_entry["status"] = "SOLVED"
                    res_entry["category"] = "Hash Cryptanalysis"
                    res_entry["vulnerability"] = f"Dictionary Recovery ({h_res.get('hash_type')})"
                    res_entry["flag"] = h_res.get("plaintext")
                    res_entry["latency_ms"] = round((time.time() - start_t) * 1000, 2)
                    return res_entry

            from verification_engine import extract_flag
            final_dec = dec_res.get("final_decoded") or ""
            if final_dec:
                f_flag = extract_flag(final_dec)
                if f_flag:
                    res_entry["status"] = "SOLVED"
                    res_entry["category"] = "Encoding Transformation"
                    res_entry["vulnerability"] = "Recursive Multi-Layer Decoding"
                    res_entry["flag"] = f_flag
                    res_entry["latency_ms"] = round((time.time() - start_t) * 1000, 2)
                    return res_entry

            # 3. Fast Classical Cryptanalysis
            from classical_crypto import analyze_and_solve_classical
            cla_res = analyze_and_solve_classical(text)
            if cla_res.get("decoded_result"):
                c_flag = extract_flag(cla_res["decoded_result"] or "")
                if c_flag:
                    res_entry["status"] = "SOLVED"
                    res_entry["category"] = "Classical Cipher"
                    res_entry["vulnerability"] = cla_res.get("top_match", {}).get("cipher", "Classical Decryption")
                    res_entry["flag"] = c_flag
                    res_entry["latency_ms"] = round((time.time() - start_t) * 1000, 2)
                    return res_entry

            # 4. Fast RSA Math Checks (Cube Root, Fermat)
            if "e" in params and "c" in params:
                from rsa_cryptanalysis import RSAAttacks
                e_val = params.get("e")
                c_val = params.get("c")
                n_val = params.get("n", 0)

                if e_val == 3 and n_val > 0:
                    r_cube = RSAAttacks.attack_small_exponent_root(c_val, e_val, n_val)
                    if r_cube and r_cube.get("plaintext"):
                        res_entry["status"] = "SOLVED"
                        res_entry["category"] = "RSA Cryptanalysis"
                        res_entry["vulnerability"] = "Small Exponent Cube Root"
                        res_entry["flag"] = r_cube.get("plaintext")
                        res_entry["latency_ms"] = round((time.time() - start_t) * 1000, 2)
                        return res_entry

                if n_val > 0:
                    r_ferm = RSAAttacks.factor_fermat(n_val, max_steps=50000)
                    if r_ferm and (r_ferm.get("status") == "solved" or r_ferm.get("p")):
                        res_entry["status"] = "SOLVED"
                        res_entry["category"] = "RSA Cryptanalysis"
                        res_entry["vulnerability"] = "Fermat Factorization (Close Primes)"
                        res_entry["flag"] = f"Factors p={r_ferm.get('p')}, q={r_ferm.get('q')}"
                        res_entry["latency_ms"] = round((time.time() - start_t) * 1000, 2)
                        return res_entry

            # If parameters and vulnerability were found with high confidence
            if res_entry["confidence"] == "HIGH":
                res_entry["status"] = "VULNERABLE"

        except Exception as e:
            res_entry["error"] = str(e)

        res_entry["latency_ms"] = round((time.time() - start_t) * 1000, 2)
        return res_entry

    def solve_batch(self, challenges: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Solves a list of challenge dictionaries concurrently.
        """
        start_all = time.time()
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_item = {executor.submit(self.solve_single, ch): ch for ch in challenges}
            for future in concurrent.futures.as_completed(future_to_item):
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    results.append({"status": "ERROR", "error": str(e)})

        # Triage Sorting: SOLVED first, then VULNERABLE, then UNSOLVED
        sort_order = {"SOLVED": 0, "VULNERABLE": 1, "UNSOLVED": 2, "ERROR": 3}
        sorted_results = sorted(results, key=lambda x: (sort_order.get(x.get("status", "UNSOLVED"), 4), x.get("latency_ms", 99999)))

        solved_count = sum(1 for r in sorted_results if r.get("status") == "SOLVED")
        vulnerable_count = sum(1 for r in sorted_results if r.get("status") == "VULNERABLE")
        total_time = round(time.time() - start_all, 2)

        return {
            "batch_id": self.batch_id,
            "total_challenges": len(challenges),
            "solved_count": solved_count,
            "vulnerable_count": vulnerable_count,
            "duration_seconds": total_time,
            "triage_leaderboard": sorted_results
        }
