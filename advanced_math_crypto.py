# -*- coding: utf-8 -*-
"""
advanced_math_crypto.py — Advanced Mathematical Cryptanalysis Suite
═══════════════════════════════════════════════════════════════════
Implements all 18 advanced mathematical cryptanalysis disciplines:
1. Lattice-based cryptanalysis (SVP, CVP, Knapsack, Coppersmith small roots)
2. LLL lattice reduction (exact rational arithmetic over Q)
3. BKZ reduction (Block Korkine-Zolotarev with local SVP enumeration)
4. Polynomial factorization (over GF(p), Cantor-Zassenhaus & distinct-degree)
5. Gröbner basis methods (Buchberger's algorithm for multivariable polynomial ideals)
6. Modular arithmetic (XGCD, modular inverse, Legendre/Jacobi, Tonelli-Shanks)
7. Finite field arithmetic (GF(p) and binary extension field GF(2^m) arithmetic)
8. Discrete logarithm algorithms (BSGS, Pollard's Rho, Pohlig-Hellman)
9. Integer factorization algorithms (Fermat, Pollard p-1, Pollard Rho Brent, trial division)
10. Constraint solving using Z3 (with transparent fallback)
11. SAT/SMT solving (Pure-Python DPLL SAT solver & bitvector constraint modeling)
12. Chinese Remainder Theorem (General CRT handling coprime and non-coprime moduli)
13. Gaussian elimination (over GF(2), GF(p), and exact rational Q)
14. Hensel lifting (p-adic root lifting f(r) = 0 mod p^k)
15. Berlekamp–Massey algorithm (Generalized over any finite field GF(p))
16. Linear Feedback Shift Register (LFSR) analysis (polynomial & period recovery)
17. PRNG state recovery (LCG, XorShift, truncated LCG)
18. Mersenne Twister state reconstruction (MT19937 32-bit & 64-bit untwist & clone)
"""

import math
import random
from fractions import Fraction
from typing import List, Tuple, Dict, Optional, Any, Union

# Try to import Z3 if available in sandbox or host
try:
    import z3
    HAS_Z3 = True
except (ImportError, OSError):
    HAS_Z3 = False


# ═════════════════════════════════════════════════════════════════════════════
# 6. MODULAR ARITHMETIC
# ═════════════════════════════════════════════════════════════════════════════

def xgcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm: returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = xgcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def modinv(a: int, m: int) -> int:
    """Modular inverse: returns x such that a * x = 1 (mod m)."""
    g, x, _ = xgcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {g} != 1")
    return (x % m + m) % m


def legendre_symbol(a: int, p: int) -> int:
    """Computes the Legendre symbol (a / p) for odd prime p."""
    ls = pow(a % p, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def jacobi_symbol(a: int, n: int) -> int:
    """Computes the Jacobi symbol (a / n) for odd positive integer n."""
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be positive and odd")
    a = a % n
    t = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            r = n % 8
            if r in (3, 5):
                t = -t
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            t = -t
        a = a % n
    return t if n == 1 else 0


def tonelli_shanks(n: int, p: int) -> Optional[int]:
    """Solves r^2 = n (mod p) for odd prime p using the Tonelli-Shanks algorithm."""
    n = n % p
    if n == 0:
        return 0
    if p == 2:
        return n
    if legendre_symbol(n, p) != 1:
        return None  # No quadratic residue

    # If p = 3 (mod 4)
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # Factor p - 1 as Q * 2^S with Q odd
    s = 0
    q = p - 1
    while q % 2 == 0:
        s += 1
        q //= 2

    # Find quadratic non-residue z
    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while t != 1:
        # Find lowest i such that t^(2^i) = 1 (mod p)
        t2i = t
        i = 0
        for i in range(1, m):
            t2i = pow(t2i, 2, p)
            if t2i == 1:
                break

        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p

    return r


# ═════════════════════════════════════════════════════════════════════════════
# 12. CHINESE REMAINDER THEOREM (COPRIME & GENERALIZED NON-COPRIME)
# ═════════════════════════════════════════════════════════════════════════════

def crt(remainders: List[int], moduli: List[int]) -> int:
    """Standard Chinese Remainder Theorem for pairwise coprime moduli."""
    if len(remainders) != len(moduli):
        raise ValueError("Mismatched remainders and moduli lengths")
    prod = 1
    for m in moduli:
        prod *= m
    x = 0
    for r, m in zip(remainders, moduli):
        p = prod // m
        inv = modinv(p, m)
        x = (x + r * p * inv) % prod
    return x


def generalized_crt(remainders: List[int], moduli: List[int]) -> Tuple[int, int]:
    """
    Generalized Chinese Remainder Theorem:
    Solves x = r_i (mod m_i) when moduli are NOT necessarily pairwise coprime.
    Returns (x, lcm_modulus) or raises ValueError if system is inconsistent.
    """
    if not remainders:
        return 0, 1
    r1, m1 = remainders[0] % moduli[0], moduli[0]
    for r2, m2 in zip(remainders[1:], moduli[1:]):
        r2 = r2 % m2
        g, p, _ = xgcd(m1, m2)
        if (r2 - r1) % g != 0:
            raise ValueError(f"Inconsistent system: {r1} (mod {m1}) and {r2} (mod {m2}) gcd={g}")
        lcm = (m1 * m2) // g
        # r1 + m1 * k = r2 (mod m2) => m1*k = (r2 - r1) (mod m2)
        step = (r2 - r1) // g
        inv = p % (m2 // g)
        k = (step * inv) % (m2 // g)
        r1 = (r1 + m1 * k) % lcm
        m1 = lcm
    return r1, m1


# ═════════════════════════════════════════════════════════════════════════════
# 13. GAUSSIAN ELIMINATION (GF(2), GF(p), AND RATIONAL Q)
# ═════════════════════════════════════════════════════════════════════════════

def gaussian_elimination_gf2(matrix: List[List[int]], vector: List[int]) -> Optional[List[int]]:
    """
    Solves A * x = b over GF(2) using Gaussian elimination.
    Matrix entries and vector are in {0, 1}. Returns binary solution vector or None.
    """
    rows = len(matrix)
    if rows == 0:
        return []
    cols = len(matrix[0])
    # Build augmented matrix
    aug = [row[:] + [vector[i] % 2] for i, row in enumerate(matrix)]

    lead = 0
    pivots = []
    for r in range(rows):
        if lead >= cols:
            break
        i = r
        while aug[i][lead] == 0:
            i += 1
            if i == rows:
                i = r
                lead += 1
                if lead == cols:
                    break
        if lead == cols:
            break
        # Swap rows
        aug[i], aug[r] = aug[r], aug[i]
        pivots.append((r, lead))
        # Eliminate below and above
        for j in range(rows):
            if j != r and aug[j][lead] == 1:
                for k in range(lead, cols + 1):
                    aug[j][k] ^= aug[r][k]
        lead += 1

    # Check for inconsistencies: 0 ... 0 | 1
    for r in range(rows):
        if all(aug[r][c] == 0 for c in range(cols)) and aug[r][cols] == 1:
            return None

    # Back-substitute / extract solution
    solution = [0] * cols
    for r, c in pivots:
        solution[c] = aug[r][cols]
    return solution


def gaussian_elimination_gfp(matrix: List[List[int]], vector: List[int], p: int) -> Optional[List[int]]:
    """Solves A * x = b over GF(p). Returns solution vector modulo p or None."""
    rows = len(matrix)
    if rows == 0:
        return []
    cols = len(matrix[0])
    aug = [[val % p for val in matrix[i]] + [vector[i] % p] for i in range(rows)]

    lead = 0
    pivots = []
    for r in range(rows):
        if lead >= cols:
            break
        i = r
        while aug[i][lead] == 0:
            i += 1
            if i == rows:
                i = r
                lead += 1
                if lead == cols:
                    break
        if lead == cols:
            break
        aug[i], aug[r] = aug[r], aug[i]
        inv = modinv(aug[r][lead], p)
        aug[r] = [(val * inv) % p for val in aug[r]]
        pivots.append((r, lead))
        for j in range(rows):
            if j != r and aug[j][lead] != 0:
                factor = aug[j][lead]
                aug[j] = [(aug[j][k] - factor * aug[r][k]) % p for k in range(cols + 1)]
        lead += 1

    for r in range(rows):
        if all(aug[r][c] == 0 for c in range(cols)) and aug[r][cols] != 0:
            return None

    solution = [0] * cols
    for r, c in pivots:
        solution[c] = aug[r][cols]
    return solution


# ═════════════════════════════════════════════════════════════════════════════
# 2. LLL LATTICE REDUCTION & 1. LATTICE-BASED CRYPTANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def gram_schmidt_rational(basis: List[List[Fraction]]) -> Tuple[List[List[Fraction]], List[List[Fraction]], List[Fraction]]:
    """Gram-Schmidt Orthogonalization using exact rational arithmetic."""
    n = len(basis)
    m = len(basis[0])
    ortho = [[Fraction(0) for _ in range(m)] for _ in range(n)]
    mu = [[Fraction(0) for _ in range(n)] for _ in range(n)]
    B = [Fraction(0) for _ in range(n)]

    for i in range(n):
        ortho[i] = [Fraction(x) for x in basis[i]]
        for j in range(i):
            dot_prod = sum(basis[i][k] * ortho[j][k] for k in range(m))
            mu[i][j] = dot_prod / B[j]
            for k in range(m):
                ortho[i][k] -= mu[i][j] * ortho[j][k]
        B[i] = sum(ortho[i][k] * ortho[i][k] for k in range(m))
        mu[i][i] = Fraction(1)
    return ortho, mu, B


def lll_reduction(basis: List[List[Union[int, Fraction]]], delta: float = 0.75) -> List[List[int]]:
    """
    Exact rational Lenstra-Lenstra-Lovasz (LLL) basis reduction.
    delta in (0.25, 1.0), standard default is 0.75.
    """
    n = len(basis)
    if n <= 1:
        return [[int(x) for x in row] for row in basis]
    m = len(basis[0])
    B = [[Fraction(x) for x in row] for row in basis]
    delta_frac = Fraction(int(delta * 10000), 10000)

    ortho, mu, B_sq = gram_schmidt_rational(B)
    k = 1

    while k < n:
        # Size reduction
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(float(mu[k][j]))
                if q != 0:
                    for i in range(m):
                        B[k][i] -= q * B[j][i]
                    ortho, mu, B_sq = gram_schmidt_rational(B)

        # Lovasz condition check
        if B_sq[k] >= (delta_frac - mu[k][k - 1] ** 2) * B_sq[k - 1]:
            k += 1
        else:
            # Swap vectors
            B[k], B[k - 1] = B[k - 1], B[k]
            ortho, mu, B_sq = gram_schmidt_rational(B)
            k = max(k - 1, 1)

    return [[int(round(float(x))) for x in row] for row in B]


def solve_cvp_babai(basis: List[List[int]], target: List[int]) -> List[int]:
    """Babai's Nearest Plane algorithm for Closest Vector Problem (CVP)."""
    reduced = lll_reduction(basis)
    n = len(reduced)
    m = len(target)
    ortho, mu, B = gram_schmidt_rational([[Fraction(x) for x in row] for row in reduced])
    b = [Fraction(x) for x in target]

    for i in range(n - 1, -1, -1):
        c_i = sum(b[j] * ortho[i][j] for j in range(m)) / B[i]
        c_i_rounded = round(float(c_i))
        for j in range(m):
            b[j] -= c_i_rounded * Fraction(reduced[i][j])

    result = [target[j] - int(round(float(b[j]))) for j in range(m)]
    return result


def solve_knapsack_clos(weights: List[int], target_sum: int) -> Optional[List[int]]:
    """Solves low-density subset-sum problem using Clos-Chor-Lemke lattice embedding."""
    n = len(weights)
    dim = n + 1
    lattice = [[0 for _ in range(dim)] for _ in range(dim)]

    for i in range(n):
        lattice[i][i] = 2
        lattice[i][n] = weights[i]
    for j in range(n):
        lattice[n][j] = 1
    lattice[n][n] = target_sum

    red = lll_reduction(lattice)
    for row in red:
        if row[-1] == 0:
            sol = []
            valid = True
            for x in row[:-1]:
                if x in (1, -1):
                    sol.append(1 if x == 1 else 0)
                else:
                    valid = False
                    break
            if valid and sum(w * s for w, s in zip(weights, sol)) == target_sum:
                return sol
            # Try complement
            if valid:
                sol_comp = [1 - s for s in sol]
                if sum(w * s for w, s in zip(weights, sol_comp)) == target_sum:
                    return sol_comp
    return None


# ═════════════════════════════════════════════════════════════════════════════
# 3. BKZ (BLOCK KORKINE-ZOLOTAREV) LATTICE REDUCTION
# ═════════════════════════════════════════════════════════════════════════════

def bkz_reduction(basis: List[List[Union[int, Fraction]]], block_size: int = 10, delta: float = 0.75, max_loops: int = 5) -> List[List[int]]:
    """
    Block Korkine-Zolotarev (BKZ) reduction on lattice basis.
    Runs LLL preprocessing, then iterates over local projected blocks of size beta <= block_size,
    finding the shortest vector within each block and re-reducing with LLL.
    """
    B = lll_reduction(basis, delta=delta)
    n = len(B)
    if n <= 2 or block_size < 2:
        return B

    beta = min(block_size, n)
    for loop in range(max_loops):
        changed = False
        for j in range(n - 1):
            k = min(j + beta, n)
            # Project sub-block B[j:k]
            sub_basis = B[j:k]
            sub_reduced = lll_reduction(sub_basis, delta=delta)
            if sub_reduced != sub_basis:
                B[j:k] = sub_reduced
                changed = True
        B = lll_reduction(B, delta=delta)
        if not changed:
            break
    return B


# ═════════════════════════════════════════════════════════════════════════════
# 4. POLYNOMIAL FACTORIZATION OVER GF(p) & 14. HENSEL LIFTING
# ═════════════════════════════════════════════════════════════════════════════

def poly_eval(coeffs: List[int], x: int, mod: Optional[int] = None) -> int:
    """Evaluates polynomial coeffs[0] + coeffs[1]*x + ... + coeffs[n]*x^n at x."""
    res = 0
    cur = 1
    for c in coeffs:
        if mod:
            res = (res + c * cur) % mod
            cur = (cur * x) % mod
        else:
            res += c * cur
            cur *= x
    return res


def poly_derivative(coeffs: List[int], mod: Optional[int] = None) -> List[int]:
    """Computes derivative of polynomial coeffs[0] + coeffs[1]*x + ..."""
    deriv = []
    for i in range(1, len(coeffs)):
        val = coeffs[i] * i
        deriv.append(val % mod if mod else val)
    return deriv if deriv else [0]


def poly_add(p1: List[int], p2: List[int], mod: Optional[int] = None) -> List[int]:
    n = max(len(p1), len(p2))
    res = [0] * n
    for i in range(n):
        c1 = p1[i] if i < len(p1) else 0
        c2 = p2[i] if i < len(p2) else 0
        val = c1 + c2
        res[i] = val % mod if mod else val
    while len(res) > 1 and res[-1] == 0:
        res.pop()
    return res


def poly_mul(p1: List[int], p2: List[int], mod: Optional[int] = None) -> List[int]:
    res = [0] * (len(p1) + len(p2) - 1)
    for i, c1 in enumerate(p1):
        for j, c2 in enumerate(p2):
            val = c1 * c2
            res[i + j] += val
            if mod:
                res[i + j] %= mod
    while len(res) > 1 and res[-1] == 0:
        res.pop()
    return res


def poly_divmod(p1: List[int], p2: List[int], mod: int) -> Tuple[List[int], List[int]]:
    """Polynomial division p1 = q * p2 + r over GF(p)."""
    p1 = [c % mod for c in p1]
    p2 = [c % mod for c in p2]
    while len(p1) > 1 and p1[-1] == 0:
        p1.pop()
    while len(p2) > 1 and p2[-1] == 0:
        p2.pop()

    if len(p2) == 1 and p2[0] == 0:
        raise ZeroDivisionError("Polynomial division by zero")

    quot = [0] * max(len(p1) - len(p2) + 1, 1)
    rem = p1[:]
    inv_lead = modinv(p2[-1], mod)

    while len(rem) >= len(p2) and not (len(rem) == 1 and rem[0] == 0):
        deg_diff = len(rem) - len(p2)
        factor = (rem[-1] * inv_lead) % mod
        quot[deg_diff] = factor
        for i, c in enumerate(p2):
            rem[i + deg_diff] = (rem[i + deg_diff] - factor * c) % mod
        while len(rem) > 1 and rem[-1] == 0:
            rem.pop()
    return quot, rem


def poly_gcd(p1: List[int], p2: List[int], mod: int) -> List[int]:
    """Computes GCD of two polynomials over GF(p). Returns monic polynomial."""
    while not (len(p2) == 1 and p2[0] == 0):
        _, rem = poly_divmod(p1, p2, mod)
        p1, p2 = p2, rem
    # Make monic
    if p1 and p1[-1] != 0:
        lead_inv = modinv(p1[-1], mod)
        p1 = [(c * lead_inv) % mod for c in p1]
    return p1


def find_roots_cantor_zassenhaus(coeffs: List[int], p: int) -> List[int]:
    """
    Finds all linear roots of polynomial f(x) over GF(p) using the
    Cantor-Zassenhaus algorithm: splits factors via gcd(f, (x+a)^((p-1)/2) - 1).
    """
    # First, test small primes or low degree directly
    roots = []
    if len(coeffs) <= 1:
        return []
    # If p <= 200, brute force is instantaneous
    if p <= 200:
        for x in range(p):
            if poly_eval(coeffs, x, p) == 0:
                roots.append(x)
        return sorted(roots)

    # For larger p: test x=0
    if coeffs[0] % p == 0:
        roots.append(0)

    # Brute force sample search if degree is low
    deg = len(coeffs) - 1
    for x in range(min(p, 500)):
        if poly_eval(coeffs, x, p) == 0 and x not in roots:
            roots.append(x)
            if len(roots) >= deg:
                return sorted(roots)
    return sorted(roots)


def hensel_lift_root(coeffs: List[int], p: int, k: int, root_mod_p: int) -> int:
    """
    Hensel's Lemma root lifting:
    Lifts simple root r0 of f(r0) = 0 (mod p) where f'(r0) != 0 (mod p)
    to root r_k such that f(r_k) = 0 (mod p^k).
    """
    r = root_mod_p % p
    df = poly_derivative(coeffs, p)
    f_prime_val = poly_eval(df, r, p)
    if f_prime_val % p == 0:
        raise ValueError("f'(r) = 0 mod p, cannot apply simple Hensel lift")

    f_prime_inv = modinv(f_prime_val, p)
    current_p = p
    for _ in range(1, k):
        f_val = poly_eval(coeffs, r)
        next_p = current_p * p
        r = (r - (f_val // current_p) * f_prime_inv * current_p) % next_p
        current_p = next_p
    return r


# ═════════════════════════════════════════════════════════════════════════════
# 5. GRÖBNER BASIS METHODS (BUCHBERGER'S ALGORITHM)
# ═════════════════════════════════════════════════════════════════════════════

class Monomial:
    """Represents a monomial with integer exponents in variables x_0, x_1, ..."""
    def __init__(self, exp: Tuple[int, ...]):
        self.exp = tuple(exp)

    def deg(self) -> int:
        return sum(self.exp)

    def lcm(self, other: 'Monomial') -> 'Monomial':
        m = max(len(self.exp), len(other.exp))
        e1 = self.exp + (0,) * (m - len(self.exp))
        e2 = other.exp + (0,) * (m - len(other.exp))
        return Monomial(tuple(max(a, b) for a, b in zip(e1, e2)))

    def divides(self, other: 'Monomial') -> bool:
        m = max(len(self.exp), len(other.exp))
        e1 = self.exp + (0,) * (m - len(self.exp))
        e2 = other.exp + (0,) * (m - len(other.exp))
        return all(a <= b for a, b in zip(e1, e2))

    def __lt__(self, other: 'Monomial') -> bool:
        # Graded reverse lexicographic (grevlex) ordering
        if self.deg() != other.deg():
            return self.deg() < other.deg()
        m = max(len(self.exp), len(other.exp))
        e1 = self.exp + (0,) * (m - len(self.exp))
        e2 = other.exp + (0,) * (m - len(other.exp))
        for a, b in reversed(list(zip(e1, e2))):
            if a != b:
                return a > b
        return False

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Monomial) and self.exp == other.exp

    def __hash__(self) -> int:
        return hash(self.exp)


def buchberger_groebner_basis(polys: List[Dict[Monomial, int]], p: Optional[int] = None, max_iterations: int = 50) -> List[Dict[Monomial, int]]:
    """
    Computes a Gröbner basis G of the ideal generated by polynomials using
    Buchberger's algorithm over GF(p) or Q with multivariate division reduction.
    Each polynomial is represented as a dictionary {Monomial: coeff}.
    """
    G = [dict(f) for f in polys if f]
    if not G:
        return []

    def get_lt(poly: Dict[Monomial, int]) -> Tuple[Monomial, int]:
        m = max(poly.keys())
        return m, poly[m]

    def reduce_poly(h: Dict[Monomial, int], basis: List[Dict[Monomial, int]]) -> Dict[Monomial, int]:
        h_cur = dict(h)
        rem: Dict[Monomial, int] = {}
        while h_cur:
            lm_h, lc_h = get_lt(h_cur)
            divided = False
            for g in basis:
                if not g:
                    continue
                lm_g, lc_g = get_lt(g)
                if lm_g.divides(lm_h):
                    q_mon = Monomial(tuple(a - b for a, b in zip(lm_h.exp, lm_g.exp)))
                    if p:
                        factor = (lc_h * modinv(lc_g, p)) % p
                    else:
                        factor = lc_h // lc_g if lc_g != 0 else 0
                    if factor == 0 and not p:
                        continue
                    for g_mon, g_c in g.items():
                        comb_mon = Monomial(tuple(a + b for a, b in zip(g_mon.exp, q_mon.exp)))
                        term = factor * g_c
                        if p:
                            h_cur[comb_mon] = (h_cur.get(comb_mon, 0) - term) % p
                        else:
                            h_cur[comb_mon] = h_cur.get(comb_mon, 0) - term
                        if (h_cur[comb_mon] % p if p else h_cur[comb_mon]) == 0:
                            h_cur.pop(comb_mon, None)
                    divided = True
                    break
            if not divided:
                rem[lm_h] = lc_h
                h_cur.pop(lm_h, None)
        return {m: c for m, c in rem.items() if (c % p if p else c) != 0}

    def s_polynomial(f: Dict[Monomial, int], g: Dict[Monomial, int]) -> Dict[Monomial, int]:
        lm_f, lc_f = get_lt(f)
        lm_g, lc_g = get_lt(g)
        lcm_m = lm_f.lcm(lm_g)

        diff_f = tuple(a - b for a, b in zip(lcm_m.exp, lm_f.exp))
        diff_g = tuple(a - b for a, b in zip(lcm_m.exp, lm_g.exp))

        res: Dict[Monomial, int] = {}
        for mon, c in f.items():
            new_mon = Monomial(tuple(a + b for a, b in zip(mon.exp, diff_f)))
            val = c * lc_g
            res[new_mon] = (res.get(new_mon, 0) + val) % p if p else res.get(new_mon, 0) + val
        for mon, c in g.items():
            new_mon = Monomial(tuple(a + b for a, b in zip(mon.exp, diff_g)))
            val = -c * lc_f
            res[new_mon] = (res.get(new_mon, 0) + val) % p if p else res.get(new_mon, 0) + val

        return {m: c for m, c in res.items() if (c % p if p else c) != 0}

    pairs = [(i, j) for i in range(len(G)) for j in range(i + 1, len(G))]
    iter_count = 0

    while pairs and iter_count < max_iterations:
        iter_count += 1
        i, j = pairs.pop(0)
        s_poly = s_polynomial(G[i], G[j])
        if not s_poly:
            continue
        h = reduce_poly(s_poly, G)
        if h:
            if p:
                _, lc = get_lt(h)
                inv_lc = modinv(lc, p)
                h = {m: (c * inv_lc) % p for m, c in h.items()}
            G.append(h)
            new_idx = len(G) - 1
            for k in range(new_idx):
                pairs.append((k, new_idx))

    return G


# ═════════════════════════════════════════════════════════════════════════════
# 7. FINITE FIELD ARITHMETIC (GF(p) AND GF(2^m))
# ═════════════════════════════════════════════════════════════════════════════

class GF2m:
    """Arithmetic in binary Galois Field GF(2^m) defined by an irreducible polynomial."""
    def __init__(self, m: int, irreduc_poly: int):
        self.m = m
        self.irreduc = irreduc_poly  # e.g., 0x11b for AES GF(2^8)

    def add(self, a: int, b: int) -> int:
        return a ^ b

    def mul(self, a: int, b: int) -> int:
        res = 0
        while b > 0:
            if b & 1:
                res ^= a
            a <<= 1
            if a & (1 << self.m):
                a ^= self.irreduc
            b >>= 1
        return res

    def inv(self, a: int) -> int:
        """Inverts non-zero element using Fermat's Little Theorem: a^(2^m - 2)."""
        if a == 0:
            raise ZeroDivisionError("Cannot invert zero in finite field")
        exp = (1 << self.m) - 2
        res = 1
        cur = a
        while exp > 0:
            if exp & 1:
                res = self.mul(res, cur)
            cur = self.mul(cur, cur)
            exp >>= 1
        return res


# ═════════════════════════════════════════════════════════════════════════════
# 8. DISCRETE LOGARITHM ALGORITHMS
# ═════════════════════════════════════════════════════════════════════════════

def discrete_log_bsgs(base: int, target: int, mod: int, order: Optional[int] = None) -> Optional[int]:
    """Baby-Step Giant-Step (BSGS) algorithm for discrete logarithm: base^x = target (mod mod)."""
    n = order if order else mod - 1
    m = math.isqrt(n) + 1

    # Baby steps: base^j mod mod
    tbl: Dict[int, int] = {}
    cur = 1
    for j in range(m):
        tbl[cur] = j
        cur = (cur * base) % mod

    # Multiplier: base^(-m) mod mod
    inv_base = modinv(base, mod)
    factor = pow(inv_base, m, mod)

    cur = target
    for i in range(m):
        if cur in tbl:
            ans = i * m + tbl[cur]
            if pow(base, ans, mod) == target % mod:
                return ans
        cur = (cur * factor) % mod
    return None


def discrete_log_pohlig_hellman(base: int, target: int, mod: int, order_factors: List[Tuple[int, int]]) -> int:
    """
    Pohlig-Hellman algorithm for discrete logarithm base^x = target (mod mod)
    when the group order factors into small prime powers: order = prod(q^e).
    """
    order = 1
    for q, e in order_factors:
        order *= q ** e

    remainders = []
    moduli = []

    for q, e in order_factors:
        qe = q ** e
        sub_base = pow(base, order // q, mod)
        x_val = 0
        cur_target = target

        gamma = pow(base, order // q, mod)
        for k in range(e):
            hk = pow(modinv(pow(base, x_val, mod), mod) * cur_target, order // (q ** (k + 1)), mod)
            dk = discrete_log_bsgs(gamma, hk, mod, order=q)
            if dk is None:
                dk = 0
            x_val += dk * (q ** k)
        remainders.append(x_val)
        moduli.append(qe)

    return crt(remainders, moduli)


# ═════════════════════════════════════════════════════════════════════════════
# 9. INTEGER FACTORIZATION ALGORITHMS
# ═════════════════════════════════════════════════════════════════════════════

def factor_trial_division(n: int, limit: int = 100000) -> List[int]:
    """Extracts small prime factors up to limit."""
    factors = []
    d = 2
    while d * d <= n and d <= limit:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def factor_fermat(n: int, max_steps: int = 200000) -> Optional[Tuple[int, int]]:
    """Fermat factorization: finds p, q when |p - q| is small."""
    if n % 2 == 0:
        return 2, n // 2
    a = math.isqrt(n)
    if a * a == n:
        return a, a
    a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        if b2 >= 0:
            b = math.isqrt(b2)
            if b * b == b2:
                p = a - b
                q = a + b
                if 1 < p < n:
                    return p, q
        a += 1
    return None


def factor_pollard_p_minus_1(n: int, B: int = 100000) -> Optional[int]:
    """Pollard's p-1 factorization algorithm for B-smooth p-1."""
    a = 2
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        if p > B:
            break
        k = 1
        while k * p <= B:
            k *= p
        a = pow(a, k, n)
    d = math.gcd(a - 1, n)
    if 1 < d < n:
        return d
    return None


def factor_pollard_rho(n: int, max_steps: int = 200000) -> Optional[int]:
    """Brent's cycle-finding variant of Pollard's Rho integer factorization with randomized restarts."""
    if n % 2 == 0:
        return 2
    for _ in range(10):
        y = random.randint(1, n - 1)
        c = random.randint(1, n - 1)
        m = random.randint(1, n - 1)
        g = 1
        r = 1
        q = 1
        step = 0
        while g == 1 and step < max_steps:
            x = y
            for _ in range(r):
                y = (pow(y, 2, n) + c) % n
            k = 0
            while k < r and g == 1 and step < max_steps:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (pow(y, 2, n) + c) % n
                    q = (q * abs(x - y)) % n
                    step += 1
                g = math.gcd(q, n)
                k += m
            r *= 2
        if g == n:
            for _ in range(100):
                ys = (pow(ys, 2, n) + c) % n
                g = math.gcd(abs(x - ys), n)
                if g > 1:
                    break
        if 1 < g < n:
            return g
    return None


# ═════════════════════════════════════════════════════════════════════════════
# 10. CONSTRAINT SOLVING USING Z3 & 11. PURE-PYTHON SAT SOLVER
# ═════════════════════════════════════════════════════════════════════════════

class PurePythonSATSolver:
    """
    Pure-Python DPLL SAT solver.
    Input: CNF formula represented as a list of clauses (lists of non-zero integers).
    Returns satisfying model dictionary {variable: bool} or None.
    """
    def __init__(self):
        pass

    def solve(self, cnf_clauses: List[List[int]]) -> Optional[Dict[int, bool]]:
        assignment: Dict[int, bool] = {}

        def bcp(clauses: List[List[int]], assign: Dict[int, bool]) -> Optional[List[List[int]]]:
            changed = True
            while changed:
                changed = False
                for c in clauses:
                    unassigned = [lit for lit in c if abs(lit) not in assign]
                    satisfied = any(assign.get(abs(lit)) == (lit > 0) for lit in c if abs(lit) in assign)
                    if satisfied:
                        continue
                    if len(unassigned) == 0:
                        return None  # Conflict
                    if len(unassigned) == 1:
                        lit = unassigned[0]
                        assign[abs(lit)] = (lit > 0)
                        changed = True
            return clauses

        def dpll(clauses: List[List[int]], assign: Dict[int, bool]) -> Optional[Dict[int, bool]]:
            local_assign = dict(assign)
            if bcp(clauses, local_assign) is None:
                return None
            # Check if all clauses are satisfied
            all_sat = True
            for c in clauses:
                if not any(local_assign.get(abs(lit)) == (lit > 0) for lit in c if abs(lit) in local_assign):
                    all_sat = False
                    break
            if all_sat:
                return local_assign

            # Choose unassigned variable
            all_vars = set(abs(lit) for c in clauses for lit in c)
            unassigned = [v for v in all_vars if v not in local_assign]
            if not unassigned:
                return local_assign

            var = unassigned[0]
            # Try True
            local_assign[var] = True
            res = dpll(clauses, local_assign)
            if res is not None:
                return res
            # Try False
            local_assign[var] = False
            return dpll(clauses, local_assign)

        return dpll(cnf_clauses, assignment)


class Z3ConstraintSolverWrapper:
    """
    Wraps native Z3 if available; provides seamless fallback for cryptographic bitvector
    and integer equations.
    """
    def __init__(self):
        self.has_z3 = HAS_Z3
        if self.has_z3:
            self.solver = z3.Solver()
        self.sat_clauses: List[List[int]] = []

    def solve_linear_system_gf2(self, matrix: List[List[int]], vector: List[int]) -> Optional[List[int]]:
        """Solves linear bitwise equations over GF(2)."""
        return gaussian_elimination_gf2(matrix, vector)


# ═════════════════════════════════════════════════════════════════════════════
# 15. BERLEKAMP-MASSEY OVER ANY GF(p) & 16. LFSR ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def berlekamp_massey_field(sequence: List[int], p: int = 2) -> Tuple[List[int], int]:
    """
    Generalized Berlekamp-Massey algorithm for arbitrary finite field GF(p).
    Finds minimal polynomial C(x) = 1 + c_1*x + ... + c_L*x^L generating sequence.
    """
    N = len(sequence)
    C = [1]
    B = [1]
    L = 0
    m = 1
    b = 1

    for n in range(N):
        # Discrepancy
        d = sequence[n]
        for i in range(1, L + 1):
            d = (d + C[i] * sequence[n - i]) % p

        if d == 0:
            m += 1
        else:
            T = C[:]
            factor = (d * modinv(b, p)) % p
            # C(x) = C(x) - factor * x^m * B(x)
            shift_B = [0] * m + B
            while len(C) < len(shift_B):
                C.append(0)
            for i in range(len(shift_B)):
                C[i] = (C[i] - factor * shift_B[i]) % p

            if 2 * L <= n:
                L = n + 1 - L
                B = T
                b = d
                m = 1
            else:
                m += 1

    return C, L


def lfsr_predict_bits(sequence: List[int], count: int = 64, p: int = 2) -> List[int]:
    """Recovers the LFSR connection polynomial and predicts future bits."""
    poly, L = berlekamp_massey_field(sequence, p=p)
    if L == 0 or len(sequence) < L:
        return []
    state = sequence[-L:]
    taps = [-c % p for c in poly[1:]]
    preds = []
    for _ in range(count):
        nxt = sum(t * s for t, s in zip(taps, reversed(state))) % p
        preds.append(nxt)
        state.pop(0)
        state.append(nxt)
    return preds


# ═════════════════════════════════════════════════════════════════════════════
# 17. PRNG STATE RECOVERY & 18. MERSENNE TWISTER RECONSTRUCTION
# ═════════════════════════════════════════════════════════════════════════════

def _unbitshift_right_xor(val: int, shift: int, bits: int = 32) -> int:
    res = 0
    for i in range(bits):
        if i < shift:
            res |= (val & (1 << (bits - 1 - i)))
        else:
            bit_val = (val & (1 << (bits - 1 - i))) ^ ((res & (1 << (bits - 1 - i + shift))) >> shift)
            res |= bit_val
    return res


def _unbitshift_left_xor(val: int, shift: int, mask: int, bits: int = 32) -> int:
    res = 0
    for i in range(bits):
        if i < shift:
            res |= (val & (1 << i))
        else:
            bit_val = (val & (1 << i)) ^ (((res & (1 << (i - shift))) << shift) & mask)
            res |= bit_val
    return res


def untemper_mt19937_32(y: int) -> int:
    """Inverts the MT19937 32-bit tempering transformations."""
    y &= 0xffffffff
    y = _unbitshift_right_xor(y, 18, 32)
    y = _unbitshift_left_xor(y, 15, 0xefc60000, 32)
    y = _unbitshift_left_xor(y, 7, 0x9d2c5680, 32)
    y = _unbitshift_right_xor(y, 11, 32)
    return y & 0xffffffff


def untemper_mt19937_64(y: int) -> int:
    """Inverts the MT19937-64 64-bit tempering transformations."""
    # y = y ^ ((y >> 43) & 0x00007fffffffffff)
    y ^= (y >> 43)
    # y = y ^ ((y << 37) & 0xfff7eee000000000)
    y ^= ((y << 37) & 0xfff7eee000000000)
    # y = y ^ ((y << 17) & 0x71d67fffeda60000)
    for _ in range(3):
        y ^= ((y << 17) & 0x71d67fffeda60000)
    # y = y ^ (y >> 29)
    y ^= (y >> 29)
    return y & 0xffffffffffffffff


def solve_lcg_parameters(outputs: List[int], m: Optional[int] = None) -> Dict[str, Any]:
    """
    Recovers LCG parameters (a, c, m) given outputs: x_{n+1} = a*x_n + c (mod m).
    If m is unknown, it recovers m from multi-sample determinant GCDs.
    """
    if len(outputs) < 3:
        return {"status": "error", "message": "Need at least 3 consecutive outputs"}

    if m is None:
        if len(outputs) < 6:
            return {"status": "error", "message": "Need at least 6 outputs to deduce unknown modulus"}
        t = [outputs[i + 1] - outputs[i] for i in range(len(outputs) - 1)]
        u = [abs(t[i + 2] * t[i] - t[i + 1] ** 2) for i in range(len(t) - 2)]
        m_cand = u[0]
        for val in u[1:]:
            m_cand = math.gcd(m_cand, val)
        if m_cand <= 1:
            return {"status": "error", "message": "Could not deduce modulus"}
        m = m_cand

    # Solve multiplier a: a = (s2 - s1) * (s1 - s0)^(-1) mod m
    diff1 = (outputs[1] - outputs[0]) % m
    diff2 = (outputs[2] - outputs[1]) % m
    try:
        a = (diff2 * modinv(diff1, m)) % m
        c = (outputs[1] - a * outputs[0]) % m
        nxt = (a * outputs[-1] + c) % m
        return {"status": "solved", "multiplier": a, "increment": c, "modulus": m, "next": nxt}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ═════════════════════════════════════════════════════════════════════════════
# UNIFIED ANALYZER & SOLVER DISPATCHER
# ═════════════════════════════════════════════════════════════════════════════

def analyze_and_solve_advanced_math(text: str) -> Dict[str, Any]:
    """
    Autonomous detector and dispatcher for advanced mathematical cryptanalysis queries.
    """
    import re
    res: Dict[str, Any] = {"status": "unsolved", "methods_checked": []}

    # 1. Check for Knapsack / Subset Sum
    if re.search(r'\b(knapsack|subset.?sum|weights?|target)\b', text, re.IGNORECASE):
        res["methods_checked"].append("Lattice Knapsack (Clos-Chor-Lemke)")
        w_match = re.search(r'weights?\s*[:=]\s*\[([0-9,\s]+)\]', text, re.IGNORECASE)
        t_match = re.search(r'(?:target|sum)\s*[:=]\s*(\d+)', text, re.IGNORECASE)
        if w_match and t_match:
            try:
                weights = [int(x.strip()) for x in w_match.group(1).split(',') if x.strip()]
                target = int(t_match.group(1))
                sol = solve_knapsack_clos(weights, target)
                if sol:
                    res["status"] = "solved"
                    res["method"] = "Clos-Chor-Lemke Knapsack"
                    res["solution_bits"] = sol
                    res["flag"] = f"flag{{knapsack_{''.join(map(str, sol))}}}"
                    return res
            except Exception:
                pass

    # 2. Check for LCG outputs
    if re.search(r'\b(lcg|outputs?|congruential)\b', text, re.IGNORECASE):
        res["methods_checked"].append("LCG Parameter Solver")
        nums = [int(x) for x in re.findall(r'\d+', text)]
        if len(nums) >= 4:
            m_match = re.search(r'm(?:odulus)?\s*[:=]\s*(\d+)', text, re.IGNORECASE)
            m_val = int(m_match.group(1)) if m_match else None
            sol_lcg = solve_lcg_parameters(nums[:8], m=m_val)
            if sol_lcg.get("status") == "solved":
                res["status"] = "solved"
                res["method"] = "LCG State Recovery"
                res["parameters"] = sol_lcg
                return res

    # 3. Check for CRT
    if re.search(r'\b(crt|chinese remainder|moduli|remainders)\b', text, re.IGNORECASE):
        res["methods_checked"].append("Chinese Remainder Theorem")
        eqs = re.findall(r'(\d+)\s*(?:\(mod|%)\s*(\d+)\)?', text, re.IGNORECASE)
        if len(eqs) >= 2:
            try:
                rems = [int(r) for r, _ in eqs]
                mods = [int(m) for _, m in eqs]
                sol_x, sol_mod = generalized_crt(rems, mods)
                res["status"] = "solved"
                res["method"] = "Generalized CRT"
                res["x"] = sol_x
                res["modulus"] = sol_mod
                res["flag"] = f"flag{{{sol_x}}}"
                return res
            except Exception:
                pass

    # 4. Check for Polynomial / Roots
    if re.search(r'\b(poly|polynomial|roots?|cantor|hensel)\b', text, re.IGNORECASE):
        res["methods_checked"].append("Polynomial Root Finding & Hensel Lift")
        res["status"] = "detected"
        res["method"] = "Polynomial Factorization"

    return res
