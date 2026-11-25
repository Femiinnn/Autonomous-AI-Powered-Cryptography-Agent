# -*- coding: utf-8 -*-
"""
attack_selector.py — Intelligent Challenge Analysis & Attack Selection Engine
═════════════════════════════════════════════════════════════════════════════
Performs autonomous parameter parsing, AST-based Python challenge analysis,
ciphertext characterization (entropy, encoding, length divisibility), candidate
hypothesis generation, and probability / computational cost prioritization.
"""

import ast
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


def parse_python_challenge_ast(code: str) -> Dict[str, Any]:
    """
    Parses Python challenge source code using the AST module to extract
    cryptographic imports, cipher modes, PRNG patterns, constants, and flaws.
    """
    results: Dict[str, Any] = {
        "is_python_code": False,
        "imports": [],
        "ciphers": [],
        "modes": [],
        "prng_generators": [],
        "detected_flaws": [],
        "extracted_constants": {},
        "suggested_attacks": []
    }

    try:
        tree = ast.parse(code)
        results["is_python_code"] = True
    except (SyntaxError, ValueError):
        # Check if code contains embedded python blocks
        code_blocks = re.findall(r"```(?:python)?\s*(.*?)```", code, re.DOTALL | re.IGNORECASE)
        if code_blocks:
            combined = "\n".join(code_blocks)
            try:
                tree = ast.parse(combined)
                results["is_python_code"] = True
            except (SyntaxError, ValueError):
                return results
        else:
            return results

    # Visitor to traverse AST nodes
    for node in ast.walk(tree):
        # 1. Imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                results["imports"].append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            results["imports"].append(mod)
            for alias in node.names:
                results["imports"].append(f"{mod}.{alias.name}")

        # 2. Variable assignments / Constants
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    # Integer constants
                    if isinstance(node.value, ast.Constant):
                        val = node.value.value
                        if isinstance(val, (int, str, bytes)):
                            results["extracted_constants"][var_name] = val
                    # List of integers
                    elif isinstance(node.value, ast.List):
                        el_list = []
                        all_ints = True
                        for el in node.value.elts:
                            if isinstance(el, ast.Constant) and isinstance(el.value, int):
                                el_list.append(el.value)
                            else:
                                all_ints = False
                                break
                        if all_ints and el_list:
                            results["extracted_constants"][var_name] = el_list

        # 3. Attribute calls (e.g. AES.MODE_ECB, random.seed)
        elif isinstance(node, ast.Attribute):
            attr_name = node.attr
            if "MODE_ECB" in attr_name:
                results["modes"].append("ECB")
                results["detected_flaws"].append("AES ECB mode without diffusion")
                results["suggested_attacks"].append("ECB Byte-at-a-Time Decryption")
            elif "MODE_CBC" in attr_name:
                results["modes"].append("CBC")
                results["suggested_attacks"].append("CBC Padding Oracle / Bit Flipping")
            elif "MODE_CTR" in attr_name:
                results["modes"].append("CTR")
                results["suggested_attacks"].append("CTR Keystream Reuse")
            elif "MODE_GCM" in attr_name:
                results["modes"].append("GCM")
                results["suggested_attacks"].append("GCM Nonce Reuse / Forbidden Attack")

        # 4. Function calls (e.g. pow(m, e, n), random.getrandbits)
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in ("getrandbits", "randint", "random", "seed"):
                results["prng_generators"].append("Python random (MT19937)")
                results["suggested_attacks"].append("MT19937 State Recovery & Untwister")
            elif func_name == "pow" and len(node.args) >= 3:
                results["ciphers"].append("RSA / Modular Exponentiation")

    # Map detected imports to ciphers
    for imp in results["imports"]:
        if "Crypto.Cipher.AES" in imp or "aes" in imp.lower():
            results["ciphers"].append("AES")
        elif "rsa" in imp.lower() or "Crypto.PublicKey.RSA" in imp:
            results["ciphers"].append("RSA")
        elif "ecc" in imp.lower() or "ecdsa" in imp.lower():
            results["ciphers"].append("ECC")
        elif "hashlib" in imp.lower():
            results["ciphers"].append("Hash")

    return results


def extract_parameters(text: str) -> Dict[str, Any]:
    """Extracts all recognized mathematical and cryptographic parameters from text and AST."""
    params: Dict[str, Any] = {}

    # 0. AST-based Python challenge parsing if code is present
    ast_data = parse_python_challenge_ast(text)
    if ast_data.get("is_python_code"):
        params["ast_analysis"] = ast_data
        for k, v in ast_data.get("extracted_constants", {}).items():
            if k in ['n', 'e', 'c', 'p', 'q', 'd', 'phi', 'dp', 'dq', 'gx', 'gy', 'qx', 'qy', 'a', 'b', 'modulus']:
                if isinstance(v, int):
                    params[k] = v
            elif k in ['weights', 'sequence', 'outputs']:
                if isinstance(v, list):
                    if k == 'weights':
                        params['weights'] = v
                    else:
                        params['sequence'] = v

    # 1. RSA / Large Integer parameters
    for var in ['n', 'e', 'c', 'p', 'q', 'd', 'phi', 'dp', 'dq']:
        if var.lower() not in params:
            m = re.search(rf'\b{var}\s*[:=]\s*([0-9a-fA-Fx]+)', text, re.IGNORECASE)
            if m:
                val_str = m.group(1)
                try:
                    params[var.lower()] = int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)
                except ValueError:
                    pass

    # 2. Elliptic Curve parameters
    for var in ['Gx', 'Gy', 'Qx', 'Qy', 'a', 'b', 'modulus', 'order']:
        if var not in params:
            m = re.search(rf'\b{var}\s*[:=]\s*([0-9a-fA-Fx]+)', text, re.IGNORECASE)
            if m:
                val_str = m.group(1)
                try:
                    params[var] = int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)
                except ValueError:
                    pass

    # 3. Knapsack / List weights & targets
    if 'weights' not in params:
        w_match = re.search(r'(?:weights?|public_key|pk)\s*[:=]\s*\[([0-9,\s]+)\]', text, re.IGNORECASE)
        if w_match:
            try:
                params['weights'] = [int(x.strip()) for x in w_match.group(1).split(',') if x.strip()]
            except ValueError:
                pass

    if 'target_sum' not in params:
        target_match = re.search(r'(?:target|sum|s)\s*[:=]\s*(\d+)', text, re.IGNORECASE)
        if target_match:
            params['target_sum'] = int(target_match.group(1))

    # 4. PRNG sequences
    if 'sequence' not in params:
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
        params = extract_parameters(challenge_text)

    hypotheses: List[AttackHypothesis] = []

    # ── AST Identified Attacks ────────────────────────────────────────────────
    ast_info = params.get("ast_analysis", {})
    if ast_info and ast_info.get("suggested_attacks"):
        for atk in ast_info["suggested_attacks"]:
            cat = "Symmetric" if any(m in atk for m in ["ECB", "CBC", "CTR", "GCM"]) else "PRNG"
            hypotheses.append(AttackHypothesis(
                name=atk,
                category=cat,
                probability=0.99,
                cost="O(1)",
                description=f"Directly verified via AST source code parsing: {', '.join(ast_info.get('detected_flaws', [atk]))}",
                handler_name=atk.lower().replace(" ", "_").replace("-", "_")
            ))

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
                probability=0.95,
                cost="O(1)",
                description="Unpadded message m^3 < N allows direct integer cube root.",
                handler_name="attack_small_exponent_root"
            ))

        # Check Wiener's condition (large e or e ~ N)
        if e and e > (n ** 0.4):
            hypotheses.append(AttackHypothesis(
                name="Wiener Continued Fractions",
                category="RSA",
                probability=0.90,
                cost="O(log N)",
                description="Small private exponent d < (1/3)*N^(1/4) via continued fraction convergents.",
                handler_name="attack_wiener"
            ))

        # Fermat factorization (close primes)
        hypotheses.append(AttackHypothesis(
            name="Fermat Factorization",
            category="RSA",
            probability=0.80,
            cost="O(isqrt(N))",
            description="Close primes |p - q| < 2^32 or small difference.",
            handler_name="factor_fermat"
        ))

        # Pollard p-1 (smooth factor)
        hypotheses.append(AttackHypothesis(
            name="Pollard's p-1",
            category="RSA",
            probability=0.75,
            cost="O(B * log N)",
            description="Prime factor p where p-1 is B-smooth.",
            handler_name="factor_pollard_p_minus_1"
        ))

        # Boneh-Durfee LLL
        hypotheses.append(AttackHypothesis(
            name="Boneh-Durfee LLL Lattice",
            category="RSA",
            probability=0.70,
            cost="O(dim^6)",
            description="Private exponent d < N^0.292 via bivariate Coppersmith lattice.",
            handler_name="attack_boneh_durfee"
        ))

    # ── Lattice / Knapsack Scenarios ───────────────────────────────────────────
    if 'weights' in params and 'target_sum' in params:
        hypotheses.append(AttackHypothesis(
            name="Clos-Chor-Lemke Subset Sum",
            category="Lattice",
            probability=0.96,
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
                probability=0.92,
                cost="O(log m)",
                description="Linear Congruential Generator multiplier and increment recovery via modular inverse.",
                handler_name="solve_lcg_parameters"
            ))

    # ── Classical / XOR Scenarios ─────────────────────────────────────────────
    chars = analyze_ciphertext_characteristics(challenge_text)
    if not (n or 'weights' in params or 'sequence' in params or ast_info):
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
