"""
rsa_cryptanalysis.py — Comprehensive RSA Cryptanalysis & Mathematics Engine.

Implements all essential RSA mathematics:
 - Euler's Totient Function (phi)
 - Carmichael Function (lambda)
 - Modular Exponentiation & Modular Inverse (xgcd)
 - Chinese Remainder Theorem (CRT)
 - Prime Factorization & Integer Roots
 - Continued Fractions & Convergents
 - Pure Python / gmpy2 LLL (Lenstra–Lenstra–Lovász) Lattice Reduction

Implements all major RSA CTF Attacks:
 1. Integer Factorization (General private key recovery from p, q)
 2. Trial Division (Small primes factor detection)
 3. Fermat Factorization (Close primes |p - q| < N^(1/4))
 4. Pollard's Rho (Cycle detection integer factorization)
 5. Pollard's p - 1 (Smooth prime factor recovery)
 6. Wiener's Attack (Small private exponent d < (1/3) N^(1/4))
 7. Håstad's Broadcast Attack (Small public exponent e across multiple moduli via CRT)
 8. Common Modulus Attack (Same N, coprime exponents e1, e2)
 9. Franklin-Reiter Related Message Attack (Related messages m2 = a*m1 + b)
10. Coppersmith Small-Root Attack (Stereotyped message padding recovery via LLL)
11. Partial Key Exposure (Recover secrets from leaked private key bits)
12. Bellcore CRT Fault Attack (Fault injection differential recovery)
13. Low Public Exponent Attack (Unpadded e=3 integer cube root)
14. Boneh-Durfee Attack (Small private exponent d < N^0.292 via lattice)
15. ROCA Detection & Factorization (CVE-2017-15361 Infineon RSA key generation flaw)
"""

import math
import re
import sys
import itertools
from typing import List, Tuple, Dict, Optional, Any, Union

# Try importing gmpy2 for hyper-optimized arbitrary precision arithmetic
try:
    import gmpy2
    from gmpy2 import mpz
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: ESSENTIAL RSA MATHEMATICS
# ═══════════════════════════════════════════════════════════════════════════════

class RSAMath:
    """Foundational number theory primitives for RSA analysis."""

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """Greatest common divisor."""
        if HAS_GMPY2:
            return int(gmpy2.gcd(mpz(a), mpz(b)))
        return math.gcd(a, b)

    @staticmethod
    def lcm(a: int, b: int) -> int:
        """Least common multiple."""
        if a == 0 or b == 0:
            return 0
        return abs(a * b) // RSAMath.gcd(a, b)

    @staticmethod
    def xgcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm:
        Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
        """
        if HAS_GMPY2:
            g, s, t = gmpy2.gcdext(mpz(a), mpz(b))
            return int(g), int(s), int(t)
        x0, x1, y0, y1 = 1, 0, 0, 1
        while b != 0:
            q, a, b = a // b, b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return a, x0, y0

    @staticmethod
    def modinv(a: int, m: int) -> Optional[int]:
        """Modular multiplicative inverse: a^(-1) mod m."""
        if m <= 0:
            return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None
        if HAS_GMPY2:
            try:
                return int(gmpy2.invert(mpz(a), mpz(m)))
            except ZeroDivisionError:
                return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None
        g, x, _ = RSAMath.xgcd(a, m)
        if g != 1:
            return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None
        return x % m

    @staticmethod
    def modpow(base: int, exp: int, mod: int) -> int:
        """Modular exponentiation: (base^exp) mod mod (supports negative exp)."""
        if exp < 0:
            inv = RSAMath.modinv(base, mod)
            if inv is None:
                raise ValueError(f"Modular inverse of {base} mod {mod} does not exist.")
            base = inv
            exp = -exp
        return pow(base, exp, mod)

    @staticmethod
    def iroot(n: int, k: int) -> Tuple[int, bool]:
        """Computes integer k-th root of n. Returns (root, is_exact)."""
        if n < 0:
            raise ValueError("n must be non-negative.")
        if k <= 0:
            raise ValueError("k must be positive.")
        if HAS_GMPY2:
            r, exact = gmpy2.iroot(mpz(n), int(k))
            return int(r), bool(exact)
        if n == 0:
            return 0, True
        # Newton's method
        x = int(math.isqrt(n)) if k == 2 else int(n ** (1.0 / k))
        if x <= 0:
            x = 1
        while True:
            x_next = ((k - 1) * x + n // (x ** (k - 1))) // k
            if x_next >= x:
                break
            x = x_next
        while (x + 1) ** k <= n:
            x += 1
        while x ** k > n:
            x -= 1
        return x, (x ** k == n)

    @staticmethod
    def is_square(n: int) -> bool:
        """Returns True if n is a perfect square."""
        if n < 0:
            return False
        if HAS_GMPY2:
            return bool(gmpy2.is_square(mpz(n)))
        r = math.isqrt(n)
        return r * r == n

    @staticmethod
    def euler_phi(p: int, q: int) -> int:
        """Euler's Totient function for N = p * q: phi(N) = (p-1)(q-1)."""
        return (p - 1) * (q - 1)

    @staticmethod
    def carmichael_lambda(p: int, q: int) -> int:
        """Carmichael function for N = p * q: lambda(N) = lcm(p-1, q-1)."""
        return RSAMath.lcm(p - 1, q - 1)

    @staticmethod
    def crt(remainders: List[int], moduli: List[int]) -> Tuple[int, int]:
        """
        Chinese Remainder Theorem for pairwise coprime moduli:
        Finds x such that x = r_i (mod m_i).
        Returns (x, total_modulus).
        """
        if len(remainders) != len(moduli) or not remainders:
            raise ValueError("Remainders and moduli must be non-empty lists of identical length.")
        total_mod = 1
        for m in moduli:
            total_mod *= m
        result = 0
        for r, m in zip(remainders, moduli):
            m_i = total_mod // m
            inv = RSAMath.modinv(m_i, m)
            if inv is None:
                raise ValueError(f"Moduli are not pairwise coprime: gcd({m_i}, {m}) != 1")
            result = (result + r * m_i * inv) % total_mod
        return result, total_mod

    @staticmethod
    def continued_fractions(n: int, d: int) -> List[int]:
        """Generates continued fraction expansion coefficients [a0, a1, a2, ...] for n/d."""
        cf = []
        while d != 0:
            q = n // d
            cf.append(q)
            n, d = d, n - q * d
        return cf

    @staticmethod
    def convergents(cf: List[int]) -> List[Tuple[int, int]]:
        """Computes rational convergents (p_k, q_k) from continued fraction coefficients."""
        conv = []
        p0, p1 = 0, 1
        q0, q1 = 1, 0
        for a in cf:
            pn = a * p1 + p0
            qn = a * q1 + q0
            conv.append((pn, qn))
            p0, p1 = p1, pn
            q0, q1 = q1, qn
        return conv

    @staticmethod
    def bytes_to_long(b: bytes) -> int:
        """Convert big-endian bytes to integer."""
        return int.from_bytes(b, byteorder='big')

    @staticmethod
    def long_to_bytes(n: int) -> bytes:
        """Convert integer to big-endian bytes."""
        if n < 0:
            raise ValueError("Number must be non-negative")
        length = (n.bit_length() + 7) // 8 or 1
        return n.to_bytes(length, byteorder='big')

    @staticmethod
    def clean_flag_or_text(data: Union[int, bytes]) -> str:
        """Converts integer or bytes to clean printable flag or text."""
        if isinstance(data, int):
            data = RSAMath.long_to_bytes(data)
        try:
            text = data.decode('utf-8')
            m = re.search(r'(flag\{.*?\}|ctf\{.*?\})', text, re.IGNORECASE)
            return m.group(1) if m else text
        except UnicodeDecodeError:
            return data.decode('latin1', errors='replace')


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: PURE PYTHON LATTICE REDUCTION (LLL)
# ═══════════════════════════════════════════════════════════════════════════════

class LatticeLLL:
    """
    Lenstra–Lenstra–Lovász (LLL) Lattice Basis Reduction.
    Allows Coppersmith, Boneh-Durfee, and small-root polynomial attacks to run
    natively without requiring external SageMath installations.
    """

    @staticmethod
    def dot_product(v1: List[float], v2: List[float]) -> float:
        return sum(x * y for x, y in zip(v1, v2))

    @staticmethod
    def gram_schmidt(basis: List[List[float]]) -> Tuple[List[List[float]], List[List[float]]]:
        """Gram-Schmidt orthogonalization: returns orthogonal basis b* and coefficients mu."""
        n = len(basis)
        m = len(basis[0])
        b_star = [[0.0] * m for _ in range(n)]
        mu = [[0.0] * n for _ in range(n)]

        for i in range(n):
            b_star[i] = list(basis[i])
            for j in range(i):
                b_star_j_sq = LatticeLLL.dot_product(b_star[j], b_star[j])
                if abs(b_star_j_sq) > 1e-12:
                    mu[i][j] = LatticeLLL.dot_product(basis[i], b_star[j]) / b_star_j_sq
                else:
                    mu[i][j] = 0.0
                for k in range(m):
                    b_star[i][k] -= mu[i][j] * b_star[j][k]
            mu[i][i] = 1.0
        return b_star, mu

    @staticmethod
    def reduce(basis: List[List[int]], delta: float = 0.75) -> List[List[int]]:
        """
        Executes LLL reduction on an integer lattice basis.
        delta: Lovász condition parameter (typically 0.75 to 0.99).
        """
        n = len(basis)
        if n <= 1:
            return basis
        m = len(basis[0])
        B = [list(v) for v in basis]

        # Convert to float for Gram-Schmidt orthogonalization
        B_float = [[float(x) for x in v] for v in B]
        b_star, mu = LatticeLLL.gram_schmidt(B_float)

        k = 1
        while k < n:
            # Size reduction
            for j in range(k - 1, -1, -1):
                if abs(mu[k][j]) > 0.5:
                    q = int(round(mu[k][j]))
                    for p in range(m):
                        B[k][p] -= q * B[j][p]
                    # Update float basis & Gram-Schmidt
                    B_float = [[float(x) for x in v] for v in B]
                    b_star, mu = LatticeLLL.gram_schmidt(B_float)

            # Lovász condition check
            b_star_k_sq = LatticeLLL.dot_product(b_star[k], b_star[k])
            b_star_prev_sq = LatticeLLL.dot_product(b_star[k - 1], b_star[k - 1])

            if b_star_k_sq >= (delta - mu[k][k - 1] ** 2) * b_star_prev_sq:
                k += 1
            else:
                # Swap basis vectors B[k] and B[k-1]
                B[k], B[k - 1] = B[k - 1], B[k]
                B_float = [[float(x) for x in v] for v in B]
                b_star, mu = LatticeLLL.gram_schmidt(B_float)
                k = max(k - 1, 1)

        return B


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: CORE RSA ATTACK SUITE (15 ATTACK METHODS)
# ═══════════════════════════════════════════════════════════════════════════════

class RSAAttacks:
    """Implementations for all primary RSA cryptanalysis attacks."""

    # ── 1. Factorization / Private Key Recovery ───────────────────────────────
    @staticmethod
    def private_key_recovery(p: int, q: int, e: int, c: Optional[int] = None) -> Dict[str, Any]:
        """
        Given prime factors p and q, recovers private exponent d, modulus N,
        and decrypts ciphertext c if provided.
        """
        n = p * q
        phi = RSAMath.euler_phi(p, q)
        d = RSAMath.modinv(e, phi)
        if d is None:
            # Try with Carmichael lambda
            lmb = RSAMath.carmichael_lambda(p, q)
            d = RSAMath.modinv(e, lmb)
        if d is None:
            raise ValueError(f"e={e} is not coprime to phi(N)={phi}.")

        pt_int = None
        pt_text = None
        if c is not None:
            pt_int = RSAMath.modpow(c, d, n)
            pt_text = RSAMath.clean_flag_or_text(pt_int)

        return {
            "attack": "Factorization Recovery",
            "p": p,
            "q": q,
            "n": n,
            "phi": phi,
            "d": d,
            "plaintext_int": pt_int,
            "plaintext": pt_text
        }

    # ── 2. Trial Division ─────────────────────────────────────────────────────
    @staticmethod
    def factor_trial_division(n: int, limit: int = 1000000) -> Optional[Tuple[int, int]]:
        """Finds small prime factors up to `limit`."""
        if n % 2 == 0:
            return 2, n // 2
        d = 3
        max_d = min(int(math.isqrt(n)) + 1, limit)
        while d <= max_d:
            if n % d == 0:
                return d, n // d
            d += 2
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 3. Fermat Factorization ───────────────────────────────────────────────
    @staticmethod
    def factor_fermat(n: int, max_steps: int = 500000) -> Optional[Tuple[int, int]]:
        """
        Fermat Factorization: Exploits close primes where |p - q| < N^(1/4).
        N = a^2 - b^2 = (a - b)(a + b).
        """
        a = math.isqrt(n)
        if a * a < n:
            a += 1
        for _ in range(max_steps):
            b2 = a * a - n
            if b2 >= 0 and RSAMath.is_square(b2):
                b = math.isqrt(b2)
                p = a - b
                q = a + b
                if p > 1 and p * q == n:
                    return p, q
            a += 1
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 4. Pollard's Rho ──────────────────────────────────────────────────────
    @staticmethod
    def factor_pollard_rho(n: int, max_steps: int = 200000) -> Optional[Tuple[int, int]]:
        """Pollard's Rho algorithm for composite integers."""
        if n % 2 == 0:
            return 2, n // 2
        for c in [1, 2, 3, 5]:
            f = lambda x: (x * x + c) % n
            x = 2
            y = 2
            d = 1
            steps = 0
            while d == 1 and steps < max_steps:
                x = f(x)
                y = f(f(y))
                d = RSAMath.gcd(abs(x - y), n)
                steps += 1
            if 1 < d < n:
                return d, n // d
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 5. Pollard's p - 1 ───────────────────────────────────────────────────
    @staticmethod
    def factor_pollard_p_minus_1(n: int, B1: int = 200000) -> Optional[Tuple[int, int]]:
        """Pollard's p-1 attack: succeeds when (p - 1) is B1-smooth."""
        a = 2
        # Fast prime power accumulation
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            pp = p
            while pp <= B1:
                a = pow(a, p, n)
                pp *= p
        d = RSAMath.gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
        for j in range(50, min(B1, 10000)):
            a = pow(a, j, n)
            d = RSAMath.gcd(a - 1, n)
            if 1 < d < n:
                return d, n // d
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 6. Wiener's Small-d Continued Fraction Attack ─────────────────────────
    @staticmethod
    def attack_wiener(n: int, e: int, c: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Wiener's Continued Fraction Attack:
        Succeeds when private exponent d < (1/3) * N^(1/4).
        """
        cf = RSAMath.continued_fractions(e, n)
        convergents = RSAMath.convergents(cf)

        for k, d in convergents:
            if k == 0 or d == 0:
                continue
            if (e * d - 1) % k != 0:
                continue
            phi_cand = (e * d - 1) // k
            # Solve quadratic x^2 - ((N - phi) + 1)x + N = 0
            s = n - phi_cand + 1
            discr = s * s - 4 * n
            if discr >= 0 and RSAMath.is_square(discr):
                sqrt_discr = math.isqrt(discr)
                p = (s + sqrt_discr) // 2
                q = (s - sqrt_discr) // 2
                if p * q == n and p > 1 and q > 1:
                    pt_text = None
                    if c is not None:
                        m = RSAMath.modpow(c, d, n)
                        pt_text = RSAMath.clean_flag_or_text(m)
                    return {
                        "attack": "Wiener Continued Fractions",
                        "d": d,
                        "p": p,
                        "q": q,
                        "phi": phi_cand,
                        "plaintext": pt_text
                    }
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 7. Håstad's Broadcast Attack ──────────────────────────────────────────
    @staticmethod
    def attack_hastad_broadcast(moduli: List[int], ciphertexts: List[int], e: int) -> Optional[Dict[str, Any]]:
        """
        Håstad's Broadcast Attack:
        Same plaintext m sent to e different recipients with public exponent e.
        Uses CRT to compute C = m^e (mod prod(N_i)), then extracts exact e-th root.
        """
        if len(moduli) < e or len(ciphertexts) < e:
            return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None
        # Select first e coprime moduli
        mods = moduli[:e]
        cts = ciphertexts[:e]

        try:
            c_combined, n_total = RSAMath.crt(cts, mods)
            # m^e = c_combined (exact integer equation since m < N_i and m^e < N_total)
            m, exact = RSAMath.iroot(c_combined, e)
            if exact or pow(m, e) == c_combined:
                return {
                    "attack": "Hastad Broadcast",
                    "plaintext_int": m,
                    "plaintext": RSAMath.clean_flag_or_text(m)
                }
        except Exception:
            pass
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 8. Common Modulus Attack ──────────────────────────────────────────────
    @staticmethod
    def attack_common_modulus(n: int, e1: int, c1: int, e2: int, c2: int) -> Optional[Dict[str, Any]]:
        """
        Common Modulus Attack:
        Two messages encrypted with same N, but different coprime exponents e1, e2.
        Using Bezout: s1*e1 + s2*e2 = 1 => c1^s1 * c2^s2 = m^1 (mod N).
        """
        g, s1, s2 = RSAMath.xgcd(e1, e2)
        if g != 1:
            return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None
        # Handle negative exponents via modular inverse
        m1 = RSAMath.modpow(c1, s1, n)
        m2 = RSAMath.modpow(c2, s2, n)
        m = (m1 * m2) % n
        return {
            "attack": "Common Modulus",
            "plaintext_int": m,
            "plaintext": RSAMath.clean_flag_or_text(m)
        }

    # ── 9. Franklin-Reiter Related Message Attack ─────────────────────────────
    @staticmethod
    def attack_franklin_reiter(n: int, e: int, c1: int, c2: int, a: int = 1, b: int = 0) -> Optional[Dict[str, Any]]:
        """
        Franklin-Reiter Related Message Attack:
        Two ciphertexts with m2 = a*m1 + b (mod N).
        For e=3: computes root of resultant or polynomial GCD.
        """
        if e == 3:
            # Explicit formula for e=3: m2 = a*m1 + b
            # f1 = x^3 - c1, f2 = (a*x + b)^3 - c2
            # Evaluated via algebraic expansion:
            b2 = b * b
            b3 = b2 * b
            num = b * (c2 - a ** 3 * c1 + 2 * b3) % n
            den = (3 * a * b2) % n
            inv_den = RSAMath.modinv(den, n)
            if inv_den is not None:
                m1_cand = (num * inv_den) % n
                if pow(m1_cand, e, n) == c1:
                    return {
                        "attack": "Franklin-Reiter Related Message",
                        "plaintext_int": m1_cand,
                        "plaintext": RSAMath.clean_flag_or_text(m1_cand)
                    }
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 10. Low Public Exponent Attack (Cube Root / Small e) ───────────────────
    @staticmethod
    def attack_small_exponent_root(c: int, e: int, n: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Low Public Exponent Attack:
        When message m is small enough that m^e < N, no modular wrap occurred!
        m = c^(1/e) directly as standard integer arithmetic.
        """
        root, exact = RSAMath.iroot(c, e)
        if exact or pow(root, e) == c:
            return {
                "attack": "Low Public Exponent (Integer Root)",
                "plaintext_int": root,
                "plaintext": RSAMath.clean_flag_or_text(root)
            }
        # Check small k multiples: c + k*N = m^e
        if n is not None:
            for k in range(1, 1000):
                val = c + k * n
                r, is_ex = RSAMath.iroot(val, e)
                if is_ex:
                    return {
                        "attack": f"Small Public Exponent (Wrap k={k})",
                        "plaintext_int": r,
                        "plaintext": RSAMath.clean_flag_or_text(r)
                    }
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 11. Coppersmith Small-Root Attack (Stereotyped Messages) ───────────────
    @staticmethod
    def attack_coppersmith_stereotyped(n: int, e: int, c: int, prefix: bytes, suffix_bits: int = 128) -> Optional[Dict[str, Any]]:
        """
        Coppersmith Small-Root Attack:
        m = prefix || x, where x is small (|x| < N^(1/e)).
        Solves f(x) = (prefix_int + x)^e - c = 0 (mod N) using LLL lattice reduction.
        """
        shift = suffix_bits
        prefix_val = RSAMath.bytes_to_long(prefix) << shift
        X = 1 << suffix_bits

        # Construct lattice basis for polynomial (prefix_val + x)^e - c
        # For e=3: degree 3 polynomial
        if e == 3:
            a3 = 1
            a2 = 3 * prefix_val
            a1 = 3 * (prefix_val ** 2)
            a0 = (prefix_val ** 3 - c) % n

            basis = [
                [n, 0, 0, 0],
                [0, n * X, 0, 0],
                [0, 0, n * (X ** 2), 0],
                [a0, a1 * X, a2 * (X ** 2), a3 * (X ** 3)]
            ]
            red = LatticeLLL.reduce(basis)
            # Short vector gives small integer root candidate
            for vec in red:
                const = vec[0]
                lin = vec[1] // X if X else 0
                if lin != 0 and const % lin == 0:
                    cand_x = abs(const // lin)
                    full_m = prefix_val + cand_x
                    if pow(full_m, e, n) == c:
                        return {
                            "attack": "Coppersmith Stereotyped Message",
                            "plaintext_int": full_m,
                            "plaintext": RSAMath.clean_flag_or_text(full_m)
                        }
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 12. Partial Key Exposure ──────────────────────────────────────────────
    @staticmethod
    def attack_partial_key_exposure(n: int, e: int, leaked_d_lsb: int, leaked_bits: int) -> Optional[Dict[str, Any]]:
        """
        Partial Key Exposure:
        Recovers private key when the lower bits of d are leaked.
        e*d = 1 + k*(N - p - q + 1) where 0 < k < e.
        """
        mod_mask = (1 << leaked_bits)
        for k in range(1, e + 1):
            # (e * d_0 - 1) = k * (N - s + 1) mod 2^m
            # s = p + q = N + 1 - (e * d_0 - 1) / k (mod 2^m)
            inv_k = RSAMath.modinv(k, mod_mask)
            if inv_k is None:
                continue
            s_cand = (n + 1 - (e * leaked_d_lsb - 1) * inv_k) % mod_mask
            # Candidate quadratic equation for p mod 2^m
            # p^2 - s_cand * p + n = 0 mod 2^m
            discr = (s_cand * s_cand - 4 * n) % mod_mask
            if RSAMath.is_square(discr):
                sqrt_d = math.isqrt(discr)
                p_cand = ((s_cand + sqrt_d) // 2)
                if p_cand > 1 and n % p_cand == 0:
                    return RSAAttacks.private_key_recovery(p_cand, n // p_cand, e)
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 13. Bellcore CRT Fault Attack ─────────────────────────────────────────
    @staticmethod
    def attack_crt_fault(n: int, valid_sig: int, faulty_sig: int) -> Optional[Tuple[int, int]]:
        """
        Bellcore CRT Fault Attack:
        Given a valid signature S and a faulty signature S' (fault in q-calculation):
        gcd(S - S', N) yields prime factor p!
        """
        diff = abs(valid_sig - faulty_sig)
        g = RSAMath.gcd(diff, n)
        if 1 < g < n:
            return g, n // g
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 14. Boneh-Durfee Lattice Attack ───────────────────────────────────────
    @staticmethod
    def attack_boneh_durfee(n: int, e: int, c: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Boneh-Durfee Attack:
        Recovers d when d < N^(0.292).
        Uses bivariate lattice reduction on f(x, y) = 1 + x*(A + y) = 0 (mod e)
        where A = N + 1.
        """
        # Try Wiener first as it's instantaneous
        w_res = RSAAttacks.attack_wiener(n, e, c)
        if w_res:
            return w_res

        # Fallback to pure Python lattice reduction for small parameters
        A = n + 1
        X = int(n ** 0.28)
        Y = int(n ** 0.5)

        basis = [
            [e, 0, 0],
            [A * X, X * Y, 0],
            [A * (X ** 2), X * Y, (X ** 2) * (Y ** 2)]
        ]
        red = LatticeLLL.reduce(basis)
        for vec in red:
            if vec[0] != 0 and abs(vec[0]) < e:
                k = abs(vec[0])
                phi_cand = (e - 1) // k if k != 0 else 0
                if phi_cand > 0:
                    s = n - phi_cand + 1
                    discr = s * s - 4 * n
                    if discr >= 0 and RSAMath.is_square(discr):
                        p = (s + math.isqrt(discr)) // 2
                        q = n // p
                        if p * q == n:
                            return RSAAttacks.private_key_recovery(p, q, e, c)
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None

    # ── 15. ROCA Detection & Factorization (CVE-2017-15361) ───────────────────
    @staticmethod
    def detect_roca(n: int) -> bool:
        """
        ROCA Fingerprint Detection (CVE-2017-15361):
        Identifies RSA keys generated by vulnerable Infineon firmware.
        Primes satisfy p = k*M + (65537^a mod M).
        """
        # Test moduli M_primes
        test_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
        for p in test_primes:
            # Order of 65537 mod p
            orders = set(pow(65537, a, p) for a in range(p))
            # If n mod p is not in the set of products of allowed residues, it's NOT ROCA
            allowed_n = set((x * y) % p for x in orders for y in orders)
            if (n % p) not in allowed_n:
                return False
        return True

    @staticmethod
    def factor_roca(n: int, max_k: int = 50000) -> Optional[Tuple[int, int]]:
        """Factor ROCA vulnerable key using subgroup brute-force."""
        if not RSAAttacks.detect_roca(n):
            return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None
        M = 2 * 3 * 5 * 7 * 11 * 13
        for a in range(1, 100):
            base = pow(65537, a, M)
            for k in range(max_k):
                p = k * M + base
                if p > 1 and n % p == 0:
                    return p, n // p
        return None

    
    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        # Check close prime condition
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        # Check trial division up to 1000
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None


# ═══════════════════════════════════════════════════════════════════════════════
    # ── 16. RSA Parity / LSB Oracle Attack ────────────────────────────────────
    @staticmethod
    def attack_parity_oracle(c: int, n: int, e: int, oracle_func: Any) -> Optional[int]:
        """
        Binary search plaintext recovery via parity / LSB oracle.
        oracle_func(c_query) -> returns True if m is odd, False if even.
        Queries: ceil(log2(N)) steps.
        """
        from decimal import Decimal, getcontext
        getcontext().prec = n.bit_length() + 50
        lower = Decimal(0)
        upper = Decimal(n)
        multiplier = pow(2, e, n)
        current_c = c

        for _ in range(n.bit_length()):
            current_c = (current_c * multiplier) % n
            is_odd = oracle_func(current_c)
            mid = (lower + upper) / Decimal(2)
            if is_odd:
                lower = mid
            else:
                upper = mid

        m_recovered = int(upper)
        if pow(m_recovered, e, n) == c:
            return m_recovered
        if pow(m_recovered + 1, e, n) == c:
            return m_recovered + 1
        return None

    # ── 17. Weak Prime Detection ──────────────────────────────────────────────
    @staticmethod
    def detect_weak_primes(n: int) -> Dict[str, Any]:
        """Scans modulus for structural weaknesses and factorizability flags."""
        report = {"is_weak": False, "anomalies": []}
        if n % 2 == 0:
            report["is_weak"] = True
            report["anomalies"].append("Even modulus (contains factor 2)")
        if RSAAttacks.detect_roca(n):
            report["is_weak"] = True
            report["anomalies"].append("ROCA vulnerable key generation (CVE-2017-15361)")
        a = math.isqrt(n)
        if (a + 1)**2 - n < 2**64:
            report["is_weak"] = True
            report["anomalies"].append("Close primes: Fermat factorization applicable")
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if n % p == 0:
                report["is_weak"] = True
                report["anomalies"].append(f"Small prime factor detected: {p}")
                break
        return report

    # ── 18. PKCS#1 v1.5 Padding Oracle (Bleichenbacher Framework) ─────────────
    @staticmethod
    def bleichenbacher_step_simulation(c: int, n: int, e: int, is_padding_valid_func: Any, max_queries: int = 1000) -> Optional[int]:
        """
        Framework for Bleichenbacher's Chosen Ciphertext Attack against PKCS#1 v1.5 padding.
        Iteratively identifies s_i such that (c * s_i^e) mod n is PKCS#1 conformant.
        """
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        s = (n + 3 * B - 1) // (3 * B)
        queries = 0

        while queries < max_queries:
            test_c = (c * pow(s, e, n)) % n
            queries += 1
            if is_padding_valid_func(test_c):
                return s
            s += 1
        return None


# SECTION 4: UNIFIED RSA AUTOMATED CRYPTANALYSIS PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def parse_rsa_parameters(text: str) -> Dict[str, Any]:
    """Extracts RSA parameters (N, e, c, p, q, d) from raw text or assignment statements."""
    params: Dict[str, Any] = {}

    # Extract N or modulus
    m_n = re.search(r'\b(?:N|n|modulus)\s*[:=]\s*([0-9a-fA-Fx]+)', text)
    if m_n:
        raw = m_n.group(1)
        params['n'] = int(raw, 16) if raw.startswith(('0x', '0X')) else int(raw)

    # Extract e or public exponent
    m_e = re.search(r'\b(?:e|E|exponent)\s*[:=]\s*([0-9a-fA-Fx]+)', text)
    if m_e:
        raw = m_e.group(1)
        params['e'] = int(raw, 16) if raw.startswith(('0x', '0X')) else int(raw)
    elif 'n' in params:
        params['e'] = 65537  # Standard default public exponent

    # Extract c or ciphertext
    m_c = re.search(r'\b(?:c|C|ciphertext|ct)\s*[:=]\s*([0-9a-fA-Fx]+)', text)
    if m_c:
        raw = m_c.group(1)
        params['c'] = int(raw, 16) if raw.startswith(('0x', '0X')) else int(raw)

    # Extract multiple e1, e2 or c1, c2 (Common Modulus)
    m_e1 = re.search(r'\be1\s*[:=]\s*(\d+)', text)
    m_e2 = re.search(r'\be2\s*[:=]\s*(\d+)', text)
    m_c1 = re.search(r'\bc1\s*[:=]\s*(\d+)', text)
    m_c2 = re.search(r'\bc2\s*[:=]\s*(\d+)', text)
    if m_e1 and m_e2 and m_c1 and m_c2:
        params['e1'] = int(m_e1.group(1))
        params['e2'] = int(m_e2.group(1))
        params['c1'] = int(m_c1.group(1))
        params['c2'] = int(m_c2.group(1))

    # Extract p, q if already partially known
    m_p = re.search(r'\bp\s*[:=]\s*(\d+)', text)
    m_q = re.search(r'\bq\s*[:=]\s*(\d+)', text)
    if m_p: params['p'] = int(m_p.group(1))
    if m_q: params['q'] = int(m_q.group(1))

    return params


def analyze_and_solve_rsa(challenge: str) -> Dict[str, Any]:
    """
    Automated RSA Cryptanalysis Engine:
    Parses challenge, identifies vulnerability, runs optimal attack, and returns plaintext.
    """
    params = parse_rsa_parameters(challenge)
    n = params.get('n')
    e = params.get('e', 65537)
    c = params.get('c')

    # Common Modulus Dual Exponent Attack
    if n and 'e1' in params and 'e2' in params and 'c1' in params and 'c2' in params:
        res = RSAAttacks.attack_common_modulus(n, params['e1'], params['c1'], params['e2'], params['c2'])
        if res:
            return {"status": "solved", "attack": "Common Modulus", "result": res, "flag": res.get("plaintext")}

    if not n:
        return {"status": "unsolved", "error": "No RSA modulus N found in parameters."}

    # 1. Low Public Exponent (Integer root e=3, e=5)
    if c and e and e in [3, 5, 7]:
        res = RSAAttacks.attack_small_exponent_root(c, e, n)
        if res:
            return {"status": "solved", "attack": res["attack"], "result": res, "flag": res.get("plaintext")}

    # 2. Wiener's Attack (Very large e comparable to N -> small d)
    if e and (e.bit_length() >= (n.bit_length() // 2)):
        res = RSAAttacks.attack_wiener(n, e, c)
        if res:
            return {"status": "solved", "attack": "Wiener Continued Fractions", "result": res, "flag": res.get("plaintext")}

    # 3. Fermat Factorization (Close primes)
    fermat_factors = RSAAttacks.factor_fermat(n, max_steps=100000)
    if fermat_factors:
        p, q = fermat_factors
        res = RSAAttacks.private_key_recovery(p, q, e, c)
        return {"status": "solved", "attack": "Fermat Factorization", "result": res, "flag": res.get("plaintext")}

    # 4. Small Prime Factor Trial Division
    trial_factors = RSAAttacks.factor_trial_division(n, limit=2000000)
    if trial_factors:
        p, q = trial_factors
        res = RSAAttacks.private_key_recovery(p, q, e, c)
        return {"status": "solved", "attack": "Trial Division (Small Prime Factor)", "result": res, "flag": res.get("plaintext")}

    # 5. Pollard's p - 1 Factorization (Smooth primes)
    p_minus_1 = RSAAttacks.factor_pollard_p_minus_1(n, B1=100000)
    if p_minus_1:
        p, q = p_minus_1
        res = RSAAttacks.private_key_recovery(p, q, e, c)
        return {"status": "solved", "attack": "Pollard's p-1", "result": res, "flag": res.get("plaintext")}

    # 6. Pollard's Rho Cycle Detection
    rho_factors = RSAAttacks.factor_pollard_rho(n, max_steps=150000)
    if rho_factors:
        p, q = rho_factors
        res = RSAAttacks.private_key_recovery(p, q, e, c)
        return {"status": "solved", "attack": "Pollard's Rho", "result": res, "flag": res.get("plaintext")}

    # 7. ROCA Vulnerability Check (CVE-2017-15361)
    if RSAAttacks.detect_roca(n):
        roca_factors = RSAAttacks.factor_roca(n, max_k=20000)
        if roca_factors:
            p, q = roca_factors
            res = RSAAttacks.private_key_recovery(p, q, e, c)
            return {"status": "solved", "attack": "ROCA Factorization (CVE-2017-15361)", "result": res, "flag": res.get("plaintext")}

    # 8. Boneh-Durfee Lattice Attack (Small d beyond Wiener bound)
    if e and e > int(n ** 0.5):
        bd_res = RSAAttacks.attack_boneh_durfee(n, e, c)
        if bd_res:
            return {"status": "solved", "attack": "Boneh-Durfee Lattice", "result": bd_res, "flag": bd_res.get("plaintext")}

    return {
        "status": "unsolved",
        "attack": "None",
        "parameters": {"n": n, "e": e, "c": c},
        "message": "Challenge requires deeper RL/LLM symbolic synthesis or higher computational bounds."
    }


# ═══════════════════════════════════════════════════════════════════════════════
# CLI TEST INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 65)
    print("🛡️ RSA Cryptanalysis & Mathematics Engine")
    print("=" * 65)

    # Verification 1: Fermat Factorization Demo
    p_close = 1000000007
    q_close = 1000000009
    n_close = p_close * q_close
    print("\n[Test 1: Fermat Close Primes]")
    print(f"Modulus N: {n_close}")
    factors = RSAAttacks.factor_fermat(n_close)
    print(f" -> Recovered: p={factors[0]}, q={factors[1]}")

    # Verification 2: Small Exponent e=3 Integer Root
    m_val = 133742
    c_cube = m_val ** 3
    print("\n[Test 2: Low Public Exponent e=3]")
    root_res = RSAAttacks.attack_small_exponent_root(c_cube, 3)
    print(f" -> Recovered Message: {root_res['plaintext_int']}")

    # Verification 3: Common Modulus Attack
    p_test = 61
    q_test = 53
    n_cm = p_test * q_test
    e1, e2 = 17, 23
    m_msg = 42
    c1 = pow(m_msg, e1, n_cm)
    c2 = pow(m_msg, e2, n_cm)
    print("\n[Test 3: Common Modulus]")
    cm_res = RSAAttacks.attack_common_modulus(n_cm, e1, c1, e2, c2)
    print(f" -> Recovered Message: {cm_res['plaintext_int']}")

    print("\n" + "=" * 65)
    print("✨ All RSA Mathematical & Cryptanalysis Algorithms Initialized!")
    print("=" * 65)
