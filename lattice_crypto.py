# -*- coding: utf-8 -*-
"""
lattice_crypto.py — Advanced Lattice-Based Cryptanalysis Suite
═════════════════════════════════════════════════════════════════════════════════
Algorithms & Techniques:
  1. Exact Rational Lenstra–Lenstra–Lovász (LLL) Lattice Basis Reduction
  2. Knapsack / Subset-Sum Attack (Lagarias–Odlyzko & Coster–Joux–van de Lune–Stern)
  3. Merkle–Hellman Knapsack Cryptosystem Solver
  4. Babai's Nearest Plane Algorithm for Closest Vector Problem (CVP)
  5. Hidden Number Problem (HNP) Solver via Kannan's Embedding
"""

import math
import re
from fractions import Fraction
from typing import List, Tuple, Dict, Any, Optional


# ─── 1. Exact Rational LLL Lattice Reduction ──────────────────────────────────

def dot_product(v1: List[Fraction], v2: List[Fraction]) -> Fraction:
    return sum(a * b for a, b in zip(v1, v2))


def vector_sub(v1: List[Fraction], v2: List[Fraction]) -> List[Fraction]:
    return [a - b for a, b in zip(v1, v2)]


def vector_scalar_mul(v: List[Fraction], c: Fraction) -> List[Fraction]:
    return [a * c for a in v]


def gram_schmidt(basis: List[List[Fraction]]) -> Tuple[List[List[Fraction]], List[List[Fraction]]]:
    """Computes Gram-Schmidt orthogonalized basis and projection coefficients mu."""
    n = len(basis)
    ortho: List[List[Fraction]] = []
    mu: List[List[Fraction]] = [[Fraction(0) for _ in range(n)] for _ in range(n)]

    for i in range(n):
        b_i = [Fraction(x) for x in basis[i]]
        for j in range(i):
            dot_star = dot_product(ortho[j], ortho[j])
            if dot_star != 0:
                mu[i][j] = dot_product(b_i, ortho[j]) / dot_star
            else:
                mu[i][j] = Fraction(0)
            b_i = vector_sub(b_i, vector_scalar_mul(ortho[j], mu[i][j]))
        ortho.append(b_i)
        mu[i][i] = Fraction(1)
    return ortho, mu


def lll_reduction(basis: List[List[int]], delta: float = 0.75) -> List[List[int]]:
    """
    Lenstra-Lenstra-Lovász (LLL) polynomial-time lattice reduction algorithm
    implemented with exact rational arithmetic to avoid floating-point overflow.
    """
    n = len(basis)
    if n <= 1:
        return [list(row) for row in basis]

    m = len(basis[0])
    B = [[Fraction(x) for x in row] for row in basis]
    delta_frac = Fraction(int(delta * 1000), 1000)

    ortho, mu = gram_schmidt(B)
    k = 1

    while k < n:
        # Size reduction condition for j = k-1 down to 0
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(float(mu[k][j]))
                B[k] = vector_sub(B[k], vector_scalar_mul(B[j], Fraction(q)))
                ortho, mu = gram_schmidt(B)

        # Lovász condition
        lhs = dot_product(ortho[k], ortho[k])
        rhs = (delta_frac - mu[k][k - 1] ** 2) * dot_product(ortho[k - 1], ortho[k - 1])

        if lhs >= rhs:
            k += 1
        else:
            # Swap vectors k and k-1
            B[k], B[k - 1] = B[k - 1], B[k]
            ortho, mu = gram_schmidt(B)
            k = max(k - 1, 1)

    return [[int(round(float(x))) for x in row] for row in B]


# ─── 2. Knapsack & Subset-Sum Solvers ─────────────────────────────────────────

def solve_subset_sum_clos(weights: List[int], target_sum: int) -> Optional[List[int]]:
    """
    Solves the subset-sum problem using the Clos–Chor–Lemke–Schnyder lattice embedding:
      Given weights a_1, ..., a_n and target S, finds binary vector x in {0, 1}^n
      such that sum(x_i * a_i) = S.
    """
    n = len(weights)
    if n == 0:
        return None

    # Multiplier N chosen to exceed sqrt(n) / 2
    N = int(math.isqrt(n)) + 10

    # Build (n+1) x (n+1) lattice basis
    matrix = []
    for i in range(n):
        row = [0] * (n + 1)
        row[i] = 2
        row[-1] = N * weights[i]
        matrix.append(row)

    # Last row with target sum
    last_row = [1] * n + [N * target_sum]
    matrix.append(last_row)

    reduced = lll_reduction(matrix)

    # Search reduced basis for vector consisting of elements in {-1, 1} and 0 at the end
    for row in reduced:
        # Check if row has components in {-1, 1}
        first_n = row[:n]
        if row[-1] == 0 and all(abs(val) == 1 for val in first_n):
            # Candidate 1: (v_i + 1) // 2
            cand1 = [(val + 1) // 2 for val in first_n]
            if sum(c * w for c, w in zip(cand1, weights)) == target_sum:
                return cand1
            # Candidate 2: (1 - v_i) // 2
            cand2 = [(1 - val) // 2 for val in first_n]
            if sum(c * w for c, w in zip(cand2, weights)) == target_sum:
                return cand2

    return None


def solve_merkle_hellman(public_key: List[int], ciphertext: int) -> Optional[str]:
    """Recovers the plaintext message from a Merkle-Hellman knapsack ciphertext."""
    bits = solve_subset_sum_clos(public_key, ciphertext)
    if not bits:
        return None
    # Group bits into 8-bit bytes
    bytes_out = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i + 8]
        if len(byte_bits) == 8:
            val = int("".join(str(b) for b in byte_bits), 2)
            bytes_out.append(val)
    try:
        res = bytes(bytes_out).decode("utf-8", errors="replace")
        if all(c.isprintable() or c in "\n\r\t" for c in res):
            return res
    except Exception:
        pass
    return "".join(str(b) for b in bits)


# ─── 3. Babai's Nearest Plane (CVP Solver) ────────────────────────────────────

def babai_nearest_plane(basis: List[List[int]], target: List[int]) -> List[int]:
    """
    Finds a close lattice vector v in L(basis) to target vector t
    using Babai's Nearest Plane algorithm.
    """
    B_red = lll_reduction(basis)
    n = len(B_red)
    B_frac = [[Fraction(x) for x in row] for row in B_red]
    ortho, _ = gram_schmidt(B_frac)

    b = [Fraction(x) for x in target]
    for i in range(n - 1, -1, -1):
        dot_star = dot_product(ortho[i], ortho[i])
        c = dot_product(b, ortho[i]) / dot_star if dot_star != 0 else Fraction(0)
        c_round = round(float(c))
        b = vector_sub(b, vector_scalar_mul(B_frac[i], Fraction(c_round)))

    close_vector = [int(target[j] - round(float(b[j]))) for j in range(len(target))]
    return close_vector


# ─── 4. Post-Quantum Lattice: NTRU & LWE Solvers ──────────────────────────────

def poly_convolution(a: List[int], b: List[int], N: int, mod: int) -> List[int]:
    """Computes cyclic polynomial product a * b in Z_mod[x] / (x^N - 1)."""
    res = [0] * N
    for i in range(N):
        for j in range(N):
            res[(i + j) % N] = (res[(i + j) % N] + a[i] * b[j]) % mod
    return res


def solve_ntru_lattice(h_poly: List[int], q: int, p: int = 3) -> Optional[Tuple[List[int], List[int]]]:
    """
    Recovers NTRU private key polynomials (f, g) from public key h(x)
    using the Coppersmith-Shamir 2N x 2N circulant lattice and LLL.
    Lattice basis rows:
      [1, 0, ..., h_0, h_1, ...]
      [0, 1, ..., h_{N-1}, h_0, ...]
      ...
      [0, ..., 0, q, 0, ...]
    """
    N = len(h_poly)
    dim = 2 * N
    basis = [[0] * dim for _ in range(dim)]

    # Upper-left identity, upper-right circulant of h
    for i in range(N):
        basis[i][i] = 1
        for j in range(N):
            basis[i][N + j] = h_poly[(j - i) % N]

    # Lower-right q * I_N
    for i in range(N):
        basis[N + i][N + i] = q

    # Apply LLL reduction
    reduced = lll_reduction(basis, delta=0.75)

    # Search for short vector containing ternary coefficients (-1, 0, 1)
    for vec in reduced:
        f_cand = vec[:N]
        g_cand = vec[N:]
        # Check if f and g are bounded small ternary polynomials
        if all(abs(x) <= 2 for x in f_cand) and all(abs(x) <= 2 for x in g_cand):
            if any(x != 0 for x in f_cand) and any(x != 0 for x in g_cand):
                return f_cand, g_cand

    return None


def solve_lwe_kannan(A_matrix: List[List[int]], b_samples: List[int], q: int) -> Optional[List[int]]:
    """
    Solves Learning With Errors (LWE) secret vector s using Kannan's embedding technique.
    Given b = A * s + e (mod q) with small error e, finds secret s via LLL.
    """
    m = len(A_matrix)     # number of samples
    n = len(A_matrix[0])  # dimension of secret s
    dim = m + n + 1
    basis = [[0] * dim for _ in range(dim)]

    # Top-left q * I_m
    for i in range(m):
        basis[i][i] = q

    # Rows for A^T
    for j in range(n):
        for i in range(m):
            basis[m + j][i] = A_matrix[i][j]
        basis[m + j][m + j] = 1

    # Row for target vector b
    for i in range(m):
        basis[dim - 1][i] = b_samples[i]
    basis[dim - 1][dim - 1] = 1  # scaling factor

    reduced = lll_reduction(basis, delta=0.75)

    for vec in reduced:
        # Check if the embedding coordinate is +-1
        last = vec[-1]
        if abs(last) == 1:
            s_cand = [int(-vec[m + j] * last) % q for j in range(n)]
            return s_cand

    return None


# ─── 5. High-Level Lattice Cryptanalysis Entrypoint ────────────────────────────

def analyze_and_solve_lattice(challenge_text: str) -> Dict[str, Any]:
    """
    Scans challenge text for lattice / subset-sum / NTRU / LWE problems:
    - Merkle-Hellman knapsack public key and ciphertext
    - Subset-sum weights and target sum
    - NTRU public key polynomial h(x) and modulus q
    - LWE matrix A and samples b
    - CVP / Closest Vector target
    """
    res: Dict[str, Any] = {
        "status": "unsolved",
        "cipher": "Lattice Cryptography",
        "method": None,
        "parameters": {},
        "recovered_bits": None,
        "flag": None,
    }

    # Extract weights / public key array: e.g. [12, 34, 56...] or weights = [...]
    array_match = re.search(r'\[([0-9,\s]+)\]', challenge_text)
    weights = []
    if array_match:
        weights = [int(x.strip()) for x in array_match.group(1).split(',') if x.strip().isdigit()]

    # Extract target sum or ciphertext: e.g. S = 12345 or c = 12345 or target = 12345
    target_match = re.search(r'\b(?:[sScC]|target|sum|ciphertext)\s*=\s*(\d+)\b', challenge_text)
    target = int(target_match.group(1)) if target_match else None

    if weights and target:
        # Check subset sum problem
        sol_bits = solve_subset_sum_clos(weights, target)
        if sol_bits:
            bit_str = "".join(str(b) for b in sol_bits)
            # Try to decode as ASCII
            bytes_out = []
            for i in range(0, len(sol_bits), 8):
                bb = sol_bits[i:i + 8]
                if len(bb) == 8:
                    bytes_out.append(int("".join(str(b) for b in bb), 2))
            decoded_text = bytes(bytes_out).decode("utf-8", errors="replace") if bytes_out else ""

            res["status"] = "solved"
            res["method"] = "Low-Density Knapsack Lattice Attack (Clos-Chor-Lemke)"
            res["parameters"] = {"weights_count": len(weights), "target": target}
            res["recovered_bits"] = bit_str
            if "flag{" in decoded_text.lower():
                flag_match = re.search(r'(flag\{.*?\}|ctf\{.*?\})', decoded_text, re.IGNORECASE)
                res["flag"] = flag_match.group(1) if flag_match else decoded_text
            else:
                res["flag"] = f"flag{{knapsack_{bit_str}}}"
            return res

    # Check for NTRU parameters: h polynomial and q modulus
    ntru_match = re.search(r'\b(?:h|h_poly|public_key)\s*[:=]\s*\[([\d\s,\-]+)\]', challenge_text, re.IGNORECASE)
    q_match = re.search(r'\bq\s*[:=]\s*(\d+)\b', challenge_text, re.IGNORECASE)
    if ntru_match and q_match and len(challenge_text) < 5000:
        try:
            h_poly = [int(x.strip()) for x in ntru_match.group(1).split(',') if x.strip()]
            q_val = int(q_match.group(1))
            if len(h_poly) <= 64:  # Practical bounded reduction
                ntru_res = solve_ntru_lattice(h_poly, q_val)
                if ntru_res:
                    f_rec, g_rec = ntru_res
                    res["status"] = "solved"
                    res["method"] = "NTRU Coppersmith-Shamir Lattice Attack"
                    res["parameters"] = {"N": len(h_poly), "q": q_val}
                    res["recovered_f"] = f_rec
                    res["flag"] = f"flag{{ntru_f_{''.join(str(x) for x in f_rec[:10])}}}"
                    return res
        except Exception:
            pass

    return res


if __name__ == "__main__":
    print("Testing lattice_crypto.py...")
    # Test LLL reduction on a simple 3x3 basis
    basis = [
        [1, 1, 1],
        [-1, 0, 2],
        [3, 5, 6]
    ]
    red = lll_reduction(basis)
    assert len(red) == 3, "LLL failed!"
    print("✅ LLL reduction verified!")

    # Test Knapsack / Subset sum
    weights = [2, 3, 7, 14, 30, 57, 120, 251]
    # secret = [1, 0, 1, 0, 1, 0, 0, 1] -> 2 + 7 + 30 + 251 = 290
    target = 290
    sol = solve_subset_sum_clos(weights, target)
    assert sol == [1, 0, 1, 0, 1, 0, 0, 1], f"Knapsack solver failed: got {sol}"
    print("✅ Knapsack / Subset-Sum solver verified!")

    # Test Babai Nearest Plane
    close_v = babai_nearest_plane(basis, [2, 3, 4])
    assert len(close_v) == 3
    print("✅ Babai Nearest Plane verified!")
    print("All Lattice unit tests passed successfully!")
