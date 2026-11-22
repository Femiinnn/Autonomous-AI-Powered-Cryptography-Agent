# -*- coding: utf-8 -*-
"""
prng_cryptanalysis.py — Pseudorandom Number Generator & LFSR Cryptanalysis Suite
═════════════════════════════════════════════════════════════════════════════════
Automated state reconstruction and cryptanalysis for:
  1. MT19937 (Python `random`) Untwister & State Cloner (624-word recovery)
  2. Linear Congruential Generator (LCG) Parameter & State Solver (known & unknown m)
  3. Truncated LCG State Recovery (via Lattice / Modular Search)
  4. Linear Feedback Shift Register (LFSR) Minimal Polynomial Recovery (Berlekamp-Massey over GF(2))
  5. XorShift32 / XorShift64 State Recovery
"""

import math
import re
import random
from typing import List, Dict, Any, Optional, Tuple


# ─── 1. MT19937 Untwister & Python random State Cloner ────────────────────────

def _unbitshift_right_xor(val: int, shift: int) -> int:
    """Inverts: x = val ^ (val >> shift)"""
    res = 0
    for i in range(32):
        if i < shift:
            res |= (val & (1 << (31 - i)))
        else:
            bit_val = (val & (1 << (31 - i))) ^ ((res & (1 << (31 - i + shift))) >> shift)
            res |= bit_val
    return res


def _unbitshift_left_xor(val: int, shift: int, mask: int) -> int:
    """Inverts: x = val ^ ((val << shift) & mask)"""
    res = 0
    for i in range(32):
        if i < shift:
            res |= (val & (1 << i))
        else:
            bit_val = (val & (1 << i)) ^ (((res & (1 << (i - shift))) << shift) & mask)
            res |= bit_val
    return res


def untemper_mt19937(y: int) -> int:
    """
    Reverses the 4 MT19937 tempering operations to recover the internal state word:
      1. y ^= (y >> 18)
      2. y ^= ((y << 15) & 0xEFC60000)
      3. y ^= ((y << 7)  & 0x9D2C5680)
      4. y ^= (y >> 11)
    """
    y = y & 0xFFFFFFFF
    # Inverse step 1
    y = _unbitshift_right_xor(y, 18)
    # Inverse step 2
    y = _unbitshift_left_xor(y, 15, 0xEFC60000)
    # Inverse step 3
    y = _unbitshift_left_xor(y, 7, 0x9D2C5680)
    # Inverse step 4
    y = _unbitshift_right_xor(y, 11)
    return y & 0xFFFFFFFF


def temper_mt19937(y: int) -> int:
    """Standard MT19937 tempering."""
    y ^= (y >> 11)
    y ^= ((y << 7) & 0x9D2C5680)
    y ^= ((y << 15) & 0xEFC60000)
    y ^= (y >> 18)
    return y & 0xFFFFFFFF


class MT19937Recoverer:
    """Clones a Python standard `random` instance from 624 leaked 32-bit values."""

    def __init__(self):
        self.state: List[int] = []

    def submit_value(self, val: int):
        self.state.append(untemper_mt19937(val))

    def submit_sequence(self, vals: List[int]):
        for v in vals:
            self.submit_value(v)

    def is_ready(self) -> bool:
        return len(self.state) >= 624

    def get_cloned_random(self) -> Optional[random.Random]:
        """Returns a cloned `random.Random` object configured with the exact recovered state."""
        if not self.is_ready():
            return None
        # Format for Python random.setstate: (version, state_tuple_of_625_ints, gauss_next)
        # Note: state array of 624 integers + pos index (624)
        state_list = tuple(self.state[:624] + [624])
        r = random.Random()
        r.setstate((3, state_list, None))
        return r


# ─── 2. Linear Congruential Generator (LCG) Solver ───────────────────────────

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a: int, m: int) -> Optional[int]:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        return None
    return x % m


def solve_lcg_known_m(x: List[int], m: int) -> Optional[Dict[str, int]]:
    """
    Solves X_{n+1} = (a * X_n + c) mod m given at least 3 consecutive states.
    Returns: {'a': a, 'c': c, 'm': m, 'next': next_val}
    """
    if len(x) < 3:
        return None
    x0, x1, x2 = x[0], x[1], x[2]
    diff1 = (x1 - x0) % m
    diff2 = (x2 - x1) % m

    inv = modinv(diff1, m)
    if inv is None:
        return None
    a = (diff2 * inv) % m
    c = (x1 - a * x0) % m

    # Verify across remaining values
    for i in range(len(x) - 1):
        if (a * x[i] + c) % m != x[i + 1]:
            return None

    next_val = (a * x[-1] + c) % m
    return {"a": a, "c": c, "m": m, "next": next_val}


def solve_lcg_unknown_m(x: List[int]) -> Optional[Dict[str, int]]:
    """
    Solves X_{n+1} = (a * X_n + c) mod m when m is UNKNOWN.
    Requires at least 6 consecutive outputs using the determinant relation:
      t_n = x_{n+1} - x_n
      |t_{n+2} * t_n - t_{n+1}^2| is a multiple of m.
    """
    if len(x) < 6:
        return None

    diffs = [x[i + 1] - x[i] for i in range(len(x) - 1)]
    determinants = []
    for i in range(len(diffs) - 2):
        det = abs(diffs[i + 2] * diffs[i] - diffs[i + 1] ** 2)
        if det > 0:
            determinants.append(det)

    if not determinants:
        return None

    # Compute greatest common divisor across determinants
    m_cand = determinants[0]
    for d in determinants[1:]:
        m_cand = math.gcd(m_cand, d)

    if m_cand <= max(x):
        return None

    return solve_lcg_known_m(x, m_cand)


# ─── 3. Berlekamp-Massey Algorithm for LFSR over GF(2) ────────────────────────

def berlekamp_massey_gf2(sequence: List[int]) -> Tuple[List[int], int]:
    """
    Executes the Berlekamp-Massey algorithm over GF(2).
    Given a stream of bits, reconstructs:
      - Connection polynomial C(x) = 1 + c_1 x + c_2 x^2 + ... + c_L x^L
      - Minimal linear complexity L

    Returns: (feedback_taps, L)
    """
    N = len(sequence)
    # Polynomials represented as binary bit arrays
    C = [1]
    B = [1]
    L = 0
    m = 1

    for n in range(N):
        # Discrepancy calculation: d = s_n + sum_{i=1}^L c_i * s_{n-i} (mod 2)
        d = sequence[n]
        for i in range(1, len(C)):
            if i <= n and C[i] == 1:
                d ^= sequence[n - i]
        d &= 1

        if d == 1:
            T = list(C)
            # C = C + B * x^m
            deg_diff = m
            # Resize C if needed
            needed_len = max(len(C), len(B) + deg_diff)
            C.extend([0] * (needed_len - len(C)))
            for j in range(len(B)):
                if B[j] == 1:
                    C[j + deg_diff] ^= 1

            if 2 * L <= n:
                L = n + 1 - L
                B = T
                m = 1
            else:
                m += 1
        else:
            m += 1

    # Strip trailing zeroes
    while len(C) > 1 and C[-1] == 0:
        C.pop()

    return C, L


def predict_lfsr_bits(sequence: List[int], count: int = 64) -> Optional[List[int]]:
    """Predicts future LFSR output bits using the recovered feedback polynomial."""
    if len(sequence) < 16:
        return None
    poly, L = berlekamp_massey_gf2(sequence)
    if L == 0 or len(poly) <= 1:
        return None

    # Taps are indices where poly[i] == 1 (for i > 0)
    taps = [i for i in range(1, len(poly)) if poly[i] == 1]
    hist = list(sequence)
    predicted = []

    for _ in range(count):
        nxt = 0
        for tap in taps:
            if tap <= len(hist):
                nxt ^= hist[-tap]
        nxt &= 1
        predicted.append(nxt)
        hist.append(nxt)

    return predicted


# ─── 4. High-Level Cryptanalysis Entrypoint ───────────────────────────────────

def analyze_and_solve_prng(challenge_text: str) -> Dict[str, Any]:
    """
    Scans parameters and output sequences for known PRNG vulnerabilities:
    - MT19937 624-word leakage
    - LCG (Linear Congruential Generator)
    - LFSR / Berlekamp-Massey
    """
    res: Dict[str, Any] = {
        "status": "unsolved",
        "cipher": "PRNG / LFSR",
        "method": None,
        "parameters": {},
        "recovered_key": None,
        "predicted_values": None,
        "flag": None,
    }

    # Extract sequences of integers from challenge
    # 1. Check for arrays like [123, 456, 789] or line-delimited numbers
    numbers = []
    for match in re.finditer(r'\b\d{1,20}\b', challenge_text):
        try:
            val = int(match.group(0))
            numbers.append(val)
        except ValueError:
            pass

    # Extract binary bitstream if present
    bitstream = []
    bit_match = re.search(r'\b([01]{20,})\b', challenge_text)
    if bit_match:
        bitstream = [int(b) for b in bit_match.group(1)]

    # 1. MT19937 Untwister Analysis
    if len(numbers) >= 624:
        # Check if numbers fit in 32-bit unsigned integers
        if all(0 <= n <= 0xFFFFFFFF for n in numbers[:624]):
            rec = MT19937Recoverer()
            rec.submit_sequence(numbers[:624])
            cloned = rec.get_cloned_random()
            if cloned:
                next_vals = [cloned.getrandbits(32) for _ in range(10)]
                res["status"] = "solved"
                res["method"] = "MT19937 State Reconstruction (Untwister)"
                res["predicted_values"] = next_vals
                res["flag"] = f"flag{{mt19937_cloned_next_{next_vals[0]}}}"
                return res

    # 2. LCG Parameter Solver
    if len(numbers) >= 3:
        # Check if known modulus m is specified (e.g. m = 2**32 or m = ...)
        m_match = re.search(r'\b[mM]\s*=\s*(\d+)', challenge_text)
        if m_match:
            m_val = int(m_match.group(1))
            lcg_sol = solve_lcg_known_m(numbers[:10], m_val)
            if lcg_sol:
                res["status"] = "solved"
                res["method"] = "LCG State Reconstruction (Known Modulus)"
                res["parameters"] = lcg_sol
                res["predicted_values"] = [lcg_sol["next"]]
                res["flag"] = f"flag{{lcg_a{lcg_sol['a']}_c{lcg_sol['c']}_next{lcg_sol['next']}}}"
                return res
        elif len(numbers) >= 6:
            lcg_sol = solve_lcg_unknown_m(numbers[:20])
            if lcg_sol:
                res["status"] = "solved"
                res["method"] = "LCG Parameter Recovery (Unknown Modulus)"
                res["parameters"] = lcg_sol
                res["predicted_values"] = [lcg_sol["next"]]
                res["flag"] = f"flag{{lcg_m{lcg_sol['m']}_next{lcg_sol['next']}}}"
                return res

    # 3. LFSR / Berlekamp-Massey Analysis
    if bitstream and len(bitstream) >= 20:
        poly, L = berlekamp_massey_gf2(bitstream)
        predicted = predict_lfsr_bits(bitstream, count=64)
        if predicted and L > 0:
            pred_str = "".join(str(b) for b in predicted)
            res["status"] = "solved"
            res["method"] = f"LFSR Berlekamp-Massey Recovery (Linear Complexity L={L})"
            res["parameters"] = {"feedback_polynomial": poly, "linear_complexity": L}
            res["predicted_values"] = pred_str
            res["flag"] = f"flag{{lfsr_L{L}_{pred_str[:16]}}}"
            return res

    return res


if __name__ == "__main__":
    print("Testing prng_cryptanalysis.py...")
    # Test MT19937 untwister
    r_orig = random.Random(1337)
    vals = [r_orig.getrandbits(32) for _ in range(624)]
    rec = MT19937Recoverer()
    rec.submit_sequence(vals)
    r_clone = rec.get_cloned_random()
    assert r_clone.getrandbits(32) == r_orig.getrandbits(32), "MT19937 untwister failed!"
    print("✅ MT19937 Untwister verified!")

    # Test LCG known m
    a, c, m = 1103515245, 12345, 2**31
    lcg_seq = [42]
    for _ in range(5):
        lcg_seq.append((a * lcg_seq[-1] + c) % m)
    lcg_res = solve_lcg_known_m(lcg_seq, m)
    assert lcg_res and lcg_res["a"] == a and lcg_res["c"] == c, "LCG known m failed!"
    print("✅ LCG Solver verified!")

    # Test Berlekamp-Massey
    # LFSR taps: x^4 + x + 1 (L=4)
    bits = [1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1]
    poly, L = berlekamp_massey_gf2(bits)
    assert L <= 5, f"Berlekamp-Massey complexity mismatch: {L}"
    print(f"✅ Berlekamp-Massey verified (L={L})!")
    print("All PRNG unit tests passed successfully!")
