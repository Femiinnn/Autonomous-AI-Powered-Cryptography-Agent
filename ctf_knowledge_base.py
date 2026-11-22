# -*- coding: utf-8 -*-
"""
ctf_knowledge_base.py — Curated CTF Cryptanalysis Knowledge Base & Exploit Recipes
═════════════════════════════════════════════════════════════════════════════════
Provides retrieval-augmented cryptanalytic guidance, exploit templates, and
mathematical formulations across RSA, ECC, Symmetric, PRNG, Lattice, Classical,
and Steganography domains.
"""

import re
from typing import List, Dict, Any


EXPLOIT_RECIPES: List[Dict[str, Any]] = [
    {
        "domain": "PRNG",
        "title": "MT19937 (Python random) State Recovery",
        "keywords": ["random", "getrandbits", "randint", "mt19937", "mersenne", "twister", "624"],
        "summary": "Reconstruct the 624-integer internal state by inverting the 4 tempering bit shifts.",
        "snippet": (
            "from prng_cryptanalysis import MT19937Recoverer\n"
            "rec = MT19937Recoverer()\n"
            "rec.submit_sequence(known_624_outputs)\n"
            "cloned_random = rec.get_cloned_random()\n"
            "predicted_next = cloned_random.getrandbits(32)\n"
        )
    },
    {
        "domain": "PRNG",
        "title": "LCG Parameter Recovery (Known / Unknown Modulus)",
        "keywords": ["lcg", "linear congruential", "multiplier", "increment", "x_{n+1}", "next_random"],
        "summary": "Given outputs, compute a = (x2 - x1)*(x1 - x0)^(-1) mod m, and recover unknown m using determinants.",
        "snippet": (
            "from prng_cryptanalysis import solve_lcg_known_m, solve_lcg_unknown_m\n"
            "sol = solve_lcg_known_m(sequence, m=modulus)\n"
            "next_val = sol['next']\n"
        )
    },
    {
        "domain": "PRNG",
        "title": "LFSR Keystream Prediction (Berlekamp-Massey)",
        "keywords": ["lfsr", "feedback", "shift register", "taps", "polynomial", "stream cipher", "berlekamp"],
        "summary": "Recovers the minimal connection polynomial C(x) over GF(2) from 2L bits using Berlekamp-Massey.",
        "snippet": (
            "from prng_cryptanalysis import berlekamp_massey_gf2, predict_lfsr_bits\n"
            "poly, L = berlekamp_massey_gf2(bit_sequence)\n"
            "future_bits = predict_lfsr_bits(bit_sequence, count=128)\n"
        )
    },
    {
        "domain": "Lattice",
        "title": "Low-Density Knapsack / Merkle-Hellman Subset-Sum Attack",
        "keywords": ["knapsack", "merkle", "hellman", "subset sum", "density", "weights", "target sum"],
        "summary": "Solves subset sum sum(x_i * a_i) = S when density < 0.9408 using Clos-Chor-Lemke lattice embedding and LLL.",
        "snippet": (
            "from lattice_crypto import solve_subset_sum_clos, lll_reduction\n"
            "bits = solve_subset_sum_clos(weights, target_sum)\n"
            "flag = bytes([int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)])\n"
        )
    },
    {
        "domain": "Lattice",
        "title": "Babai Nearest Plane Algorithm (CVP)",
        "keywords": ["cvp", "closest vector", "babai", "lattice", "nearest plane", "embedded"],
        "summary": "Finds a lattice vector close to a given target vector within the bounded distance.",
        "snippet": (
            "from lattice_crypto import babai_nearest_plane\n"
            "close_vec = babai_nearest_plane(basis, target_vector)\n"
        )
    },
    {
        "domain": "Steganography",
        "title": "Image LSB and Trailing EOF Data Carving",
        "keywords": ["png", "jpg", "jpeg", "image", "stego", "lsb", "iend", "trailing", "exif"],
        "summary": "Carves hidden data past image EOF markers and extracts Least Significant Bit planes across color channels.",
        "snippet": (
            "from crypto_stego import analyze_and_solve_stego\n"
            "res = analyze_and_solve_stego(image_path_or_bytes)\n"
            "flag = res.get('flag')\n"
        )
    },
    {
        "domain": "RSA",
        "title": "Wiener Continued Fraction Attack on Small d",
        "keywords": ["wiener", "small d", "continued fraction", "convergents", "rsa"],
        "summary": "Recovers private exponent d when d < (1/3) * N^(1/4) via convergents of e/N.",
        "snippet": (
            "from rsa_cryptanalysis import analyze_and_solve_rsa\n"
            "res = analyze_and_solve_rsa(f'N = {N}\\ne = {e}\\nc = {c}')\n"
        )
    },
    {
        "domain": "ECC",
        "title": "Smart's Attack on Anomalous Curves (#E(Fp) = p)",
        "keywords": ["smart", "anomalous", "order p", "trace of frobenius 1", "ecdlp"],
        "summary": "Solves ECDLP in O(log^3 p) using Hensel lifting to p-adic formal group logarithms.",
        "snippet": (
            "from ecc_cryptanalysis import smart_attack\n"
            "d = smart_attack(p, a, b, P, Q)\n"
        )
    },
    {
        "domain": "Symmetric",
        "title": "CBC Padding Oracle Attack (Vaudenay)",
        "keywords": ["padding oracle", "pkcs7", "cbc", "padding error", "oracle"],
        "summary": "Recovers plaintext byte-by-byte by manipulating IV and previous ciphertext block.",
        "snippet": (
            "from symmetric_cryptanalysis import SymmetricAttacks\n"
            "pt = SymmetricAttacks.padding_oracle_attack(oracle_func, ciphertext, iv, block_size=16)\n"
        )
    }
]


def retrieve_attack_guidance(query: str, top_k: int = 2) -> List[Dict[str, Any]]:
    """
    Scans the query against curated CTF exploit recipes and returns top matching
    cryptanalytic guidance.
    """
    q_tokens = set(re.findall(r'[a-zA-Z0-9_\-]+', query.lower()))
    scored: List[Tuple[int, Dict[str, Any]]] = []

    for recipe in EXPLOIT_RECIPES:
        score = 0
        for kw in recipe["keywords"]:
            if kw.lower() in q_tokens:
                score += 3
            elif any(kw.lower() in t for t in q_tokens):
                score += 1
        if recipe["domain"].lower() in q_tokens:
            score += 2

        if score > 0:
            scored.append((score, recipe))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in scored[:top_k]]
