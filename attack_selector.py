# -*- coding: utf-8 -*-
"""
attack_selector.py — Intelligent Challenge Analysis & Attack Selection Engine
═════════════════════════════════════════════════════════════════════════════
Performs autonomous parameter parsing, ciphertext characterization (entropy,
encoding, length divisibility), candidate hypothesis generation, and probability
/ computational cost prioritization.
"""

import math
import re
from typing import Dict, List, Optional, Any, Tuple


class AttackHypothesis(dict):
    """Represents a candidate attack strategy with confidence and computational cost."""
    def __init__(self, name: str, category: str, probability: float, cost: str, description: str, handler_name: str):
        super().__init__()
        self.name = name
        self.category = category
        self.probability = probability
        self.cost = cost  # e.g., 'O(1)', 'O(log N)', 'O(sqrt N)', 'O(N^0.25)', 'O(2^k)'
        self.description = description
        self.handler_name = handler_name
        self.update({
            "name": name,
            "attack": name,
            "category": category,
            "probability": round(probability, 3),
            "cost": cost,
            "estimated_cost": cost,
            "description": description,
            "rationale": description,
            "handler_name": handler_name
        })

    def to_dict(self) -> Dict[str, Any]:
        return dict(self)


def compute_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_parameters(text: str) -> Dict[str, Any]:
    """Extracts all recognized mathematical and cryptographic parameters from text."""
    params: Dict[str, Any] = {}

    # 1. RSA / Large Integer parameters
    for var in ['n', 'e', 'c', 'p', 'q', 'd', 'phi', 'dp', 'dq']:
        m = re.search(rf'\b{var}\s*[:=]\s*([0-9a-fA-Fx]+)', text, re.IGNORECASE)
        if m:
            val_str = m.group(1)
            try:
                params[var.lower()] = int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)
            except ValueError:
                pass

    # 2. Elliptic Curve parameters
    for var in ['Gx', 'Gy', 'Qx', 'Qy', 'a', 'b', 'modulus', 'order']:
        m = re.search(rf'\b{var}\s*[:=]\s*([0-9a-fA-Fx]+)', text, re.IGNORECASE)
        if m:
            val_str = m.group(1)
            try:
                params[var] = int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)
            except ValueError:
                pass

    # 3. Knapsack / List weights & targets
    w_match = re.search(r'(?:weights?|public_key|pk)\s*[:=]\s*\[([0-9,\s]+)\]', text, re.IGNORECASE)
    if w_match:
        try:
            params['weights'] = [int(x.strip()) for x in w_match.group(1).split(',') if x.strip()]
        except ValueError:
            pass

    target_match = re.search(r'(?:target|sum|s)\s*[:=]\s*(\d+)', text, re.IGNORECASE)
    if target_match:
        params['target_sum'] = int(target_match.group(1))

    # 4. PRNG sequences
    seq_match = re.search(r'(?:outputs?|states?|sequence)\s*[:=]\s*\[([0-9,\s]+)\]', text, re.IGNORECASE)
    if seq_match:
        try:
            params['sequence'] = [int(x.strip()) for x in seq_match.group(1).split(',') if x.strip()]
        except ValueError:
            pass

    # 5. Hashes
    hex_candidates = re.findall(r'\b[0-9a-fA-F]{32,128}\b', text)
    if hex_candidates:
        params['hash_candidates'] = hex_candidates

    return params


def analyze_ciphertext_characteristics(text: str) -> Dict[str, Any]:
    """Analyzes string/binary properties of candidate ciphertexts."""
    chars = {
        "is_hex": bool(re.fullmatch(r'[0-9a-fA-F\s]+', text.strip())),
        "is_base64": bool(re.fullmatch(r'[A-Za-z0-9+/=\s]+', text.strip())) and len(text.strip()) % 4 == 0,
        "is_printable": all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in text),
        "length": len(text.strip()),
        "entropy": compute_shannon_entropy(text.encode('latin1', errors='ignore'))
    }
    return chars


def rank_attack_strategies(arg1: Any = None, arg2: Any = None, arg3: Any = None) -> List[AttackHypothesis]:
    """
    Evaluates challenge indicators and returns prioritized attack hypotheses
    sorted by probability and computational cost. Accepts (challenge_text, params)
    or (params, characteristics, challenge_text).
    """
    if isinstance(arg1, dict):
        params = arg1
        challenge_text = str(arg3 or arg2 or "")
    elif isinstance(arg2, dict):
        challenge_text = str(arg1 or "")
        params = arg2
    else:
        challenge_text = str(arg1 or "")
        params = {}

    hypotheses: List[AttackHypothesis] = []

    # ── RSA Scenarios ──────────────────────────────────────────────────────────
    n = params.get('n')
    e = params.get('e')
    c = params.get('c')
    if n and c:
        # Check low exponent cube root
        if e == 3:
            hypotheses.append(AttackHypothesis(
                name="Small Public Exponent Integer Root",
                category="RSA",
                probability=0.92,
                cost="O(1)",
                description="Unpadded message m^3 < N allows direct integer cube root.",
                handler_name="attack_small_exponent_root"
            ))

        # Check Wiener's condition (large e or e ~ N)
        if e and e > (n ** 0.4):
            hypotheses.append(AttackHypothesis(
                name="Wiener Continued Fractions",
                category="RSA",
                probability=0.88,
                cost="O(log N)",
                description="Small private exponent d < (1/3)*N^(1/4) via continued fraction convergents.",
                handler_name="attack_wiener"
            ))

        # Fermat factorization (close primes)
        hypotheses.append(AttackHypothesis(
            name="Fermat Factorization",
            category="RSA",
            probability=0.75,
            cost="O(isqrt(N))",
            description="Close primes |p - q| < 2^32 or small difference.",
            handler_name="factor_fermat"
        ))

        # Pollard p-1 (smooth factor)
        hypotheses.append(AttackHypothesis(
            name="Pollard's p-1",
            category="RSA",
            probability=0.70,
            cost="O(B * log N)",
            description="Prime factor p where p-1 is B-smooth.",
            handler_name="factor_pollard_p_minus_1"
        ))

        # Boneh-Durfee LLL
        hypotheses.append(AttackHypothesis(
            name="Boneh-Durfee LLL Lattice",
            category="RSA",
            probability=0.65,
            cost="O(dim^6)",
            description="Private exponent d < N^0.292 via bivariate Coppersmith lattice.",
            handler_name="attack_boneh_durfee"
        ))

    # ── Lattice / Knapsack Scenarios ───────────────────────────────────────────
    if 'weights' in params and 'target_sum' in params:
        hypotheses.append(AttackHypothesis(
            name="Clos-Chor-Lemke Subset Sum",
            category="Lattice",
            probability=0.95,
            cost="O(n^4)",
            description="Low-density knapsack subset-sum embedded into (n+1)x(n+1) lattice via LLL.",
            handler_name="solve_knapsack_clos"
        ))

    # ── PRNG / LFSR Scenarios ──────────────────────────────────────────────────
    if 'sequence' in params:
        seq = params['sequence']
        if len(seq) >= 624:
            hypotheses.append(AttackHypothesis(
                name="MT19937 State Recovery & Untwister",
                category="PRNG",
                probability=0.98,
                cost="O(1)",
                description="Inverts 624 32-bit outputs to reconstruct full Mersenne Twister internal state.",
                handler_name="untemper_mt19937_32"
            ))
        elif len(seq) >= 3:
            hypotheses.append(AttackHypothesis(
                name="LCG Parameter Recovery",
                category="PRNG",
                probability=0.90,
                cost="O(log m)",
                description="Linear Congruential Generator multiplier and increment recovery via modular inverse.",
                handler_name="solve_lcg_parameters"
            ))

    # ── Classical / XOR Scenarios ─────────────────────────────────────────────
    chars = analyze_ciphertext_characteristics(challenge_text)
    if not (n or 'weights' in params or 'sequence' in params):
        if chars["is_hex"] or chars["is_base64"]:
            hypotheses.append(AttackHypothesis(
                name="Single-Byte & Repeating-Key XOR",
                category="XOR",
                probability=0.85,
                cost="O(L)",
                description="Statistical byte frequency and Index of Coincidence key length estimation.",
                handler_name="repeating_key_xor_solve"
            ))
        if chars["is_printable"]:
            hypotheses.append(AttackHypothesis(
                name="Classical Substitution & Transposition",
                category="Classical",
                probability=0.80,
                cost="O(26 * L)",
                description="Caesar, Affine, Vigenere, and Columnar Transposition scored via English quadgrams.",
                handler_name="analyze_and_solve_classical"
            ))

    # Cost order weighting
    cost_weights = {
        "O(1)": 1.0,
        "O(L)": 0.95,
        "O(26 * L)": 0.90,
        "O(log N)": 0.85,
        "O(log m)": 0.85,
        "O(n^4)": 0.75,
        "O(isqrt(N))": 0.70,
        "O(B * log N)": 0.65,
        "O(dim^6)": 0.50,
    }

    # Sort descending by priority = probability * cost_weight
    hypotheses.sort(key=lambda h: h.probability * cost_weights.get(h.cost, 0.5), reverse=True)
    return hypotheses
