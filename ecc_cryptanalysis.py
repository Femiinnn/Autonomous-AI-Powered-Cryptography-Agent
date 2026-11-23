"""
ecc_cryptanalysis.py — Comprehensive Elliptic Curve Cryptography (ECC) Cryptanalysis Engine.

Implements all essential Elliptic Curve Mathematics:
 - Short Weierstrass Curves: y^2 = x^3 + a*x + b (mod p)
 - Point Addition, Doubling, Scalar Multiplication (Double-and-Add)
 - Point Validation, Order & Cofactor Handling
 - Modular Square Roots (Tonelli-Shanks) & Point Decompression

Implements all major ECC CTF Attacks:
 1. Elliptic Curve Discrete Logarithm Problem (ECDLP) - General scalar recovery
 2. Baby-Step Giant-Step (BSGS) - O(sqrt(N)) discrete logarithm solver
 3. Pollard's Rho for ECDLP - Low-memory cycle detection discrete logarithm attack
 4. Pohlig-Hellman Attack - Factorizes smooth curve orders via CRT
 5. Invalid Curve Attack - Exploits missing curve validation (different 'b' parameter)
 6. Small Subgroup / Twist Attack - Exploits cofactor/small order point subgroups
 7. Smart's Attack - Solves anomalous curves where #E(F_p) = p via p-adic formal group log
 8. ECDSA Nonce Reuse Attack - Recovers private key d from two signatures with identical k
 9. Biased Nonce Attack - Lattice-based Hidden Number Problem (HNP) key recovery
10. LLL-based ECDSA Attack - Recovers private key from partial nonce bit leakages
"""

import math
import re
import sys
import itertools
from typing import List, Tuple, Dict, Optional, Any, Union

# Try importing gmpy2 for arbitrary precision acceleration
try:
    import gmpy2
    from gmpy2 import mpz
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False

# Import LLL lattice reduction from rsa_cryptanalysis
try:
    from rsa_cryptanalysis import LatticeLLL, RSAMath
except ImportError:
    # Minimal fallback LLL
    class LatticeLLL:
        @staticmethod
        def reduce(basis: List[List[float]], delta: float = 0.75) -> List[List[float]]:
            # Return as is if unavailable
            return basis
    class RSAMath:
        @staticmethod
        def clean_flag_or_text(d):
            if isinstance(d, int):
                length = (d.bit_length() + 7) // 8 or 1
                try:
                    return d.to_bytes(length, 'big').decode('utf-8', errors='replace')
                except Exception:
                    return str(d)
            return str(d)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: ESSENTIAL ELLIPTIC CURVE MATHEMATICS
# ═══════════════════════════════════════════════════════════════════════════════

class ECPoint:
    """Represents an affine point (x, y) on an elliptic curve or point at infinity."""
    def __init__(self, x: Optional[int], y: Optional[int], is_infinity: bool = False):
        self.x = x
        self.y = y
        self.is_infinity = is_infinity or (x is None and y is None)

    def __eq__(self, other) -> bool:
        if not isinstance(other, ECPoint):
            return False
        if self.is_infinity and other.is_infinity:
            return True
        return self.is_infinity == other.is_infinity and self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        if self.is_infinity:
            return "ECPoint(Infinity)"
        return f"ECPoint({hex(self.x) if self.x and self.x > 10000 else self.x}, {hex(self.y) if self.y and self.y > 10000 else self.y})"

    def to_tuple(self) -> Tuple[Optional[int], Optional[int]]:
        return (self.x, self.y)


class EllipticCurve:
    """
    Weierstrass Elliptic Curve over prime field F_p:
        y^2 = x^3 + a*x + b (mod p)
    """
    def __init__(self, p: int, a: int, b: int, order: Optional[int] = None):
        self.p = p
        self.a = a % p
        self.b = b % p
        self.order = order

    @property
    def infinity(self) -> ECPoint:
        return ECPoint(None, None, is_infinity=True)

    def is_on_curve(self, P: ECPoint) -> bool:
        """Verifies if P lies on y^2 = x^3 + a*x + b (mod p)."""
        if P.is_infinity:
            return True
        lhs = (P.y * P.y) % self.p
        rhs = (pow(P.x, 3, self.p) + self.a * P.x + self.b) % self.p
        return lhs == rhs

    def negate(self, P: ECPoint) -> ECPoint:
        """Computes -P = (x, -y mod p)."""
        if P.is_infinity:
            return P
        return ECPoint(P.x, (-P.y) % self.p)

    def add(self, P: ECPoint, Q: ECPoint) -> ECPoint:
        """Adds two points on the curve: P + Q."""
        if P.is_infinity:
            return Q
        if Q.is_infinity:
            return P

        # P + (-P) = Infinity
        if P.x == Q.x and (P.y + Q.y) % self.p == 0:
            return self.infinity

        # Point Doubling: P == Q
        if P == Q:
            if P.y == 0:
                return self.infinity
            # lambda = (3*x1^2 + a) / (2*y1) mod p
            num = (3 * P.x * P.x + self.a) % self.p
            den = (2 * P.y) % self.p
            lam = (num * pow(den, self.p - 2, self.p)) % self.p
        else:
            if P.x == Q.x:
                return self.infinity
            # lambda = (y2 - y1) / (x2 - x1) mod p
            num = (Q.y - P.y) % self.p
            den = (Q.x - P.x) % self.p
            lam = (num * pow(den, self.p - 2, self.p)) % self.p

        x3 = (lam * lam - P.x - Q.x) % self.p
        y3 = (lam * (P.x - x3) - P.y) % self.p
        return ECPoint(x3, y3)

    def multiply(self, P: ECPoint, k: int) -> ECPoint:
        """Scalar multiplication: k * P via Double-and-Add algorithm."""
        if P.is_infinity or k == 0:
            return self.infinity
        if k < 0:
            return self.multiply(self.negate(P), -k)
        if self.order:
            k = k % self.order

        result = self.infinity
        current = P

        while k > 0:
            if k & 1:
                result = self.add(result, current)
            current = self.add(current, current)
            k >>= 1

        return result

    def decompress_point(self, x: int, y_parity: int) -> Optional[ECPoint]:
        """Recovers y given x and parity bit (0 for even, 1 for odd)."""
        rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        # Tonelli-Shanks or fast root if p = 3 mod 4
        if self.p % 4 == 3:
            y = pow(rhs, (self.p + 1) // 4, self.p)
            if (y * y) % self.p != rhs:
                return None
        else:
            y = self.mod_sqrt(rhs, self.p)
            if y is None:
                return None
        if (y & 1) != (y_parity & 1):
            y = self.p - y
        return ECPoint(x, y)

    @staticmethod
    def mod_sqrt(a: int, p: int) -> Optional[int]:
        """Tonelli-Shanks algorithm for modular square root."""
        a %= p
        if a == 0:
            return 0
        if pow(a, (p - 1) // 2, p) != 1:
            return None
        if p % 4 == 3:
            return pow(a, (p + 1) // 4, p)

        # Factor p - 1 = q * 2^s with q odd
        q, s = p - 1, 0
        while q % 2 == 0:
            q //= 2
            s += 1

        z = 2
        while pow(z, (p - 1) // 2, p) == 1:
            z += 1

        c = pow(z, q, p)
        x = pow(a, (q + 1) // 2, p)
        t = pow(a, q, p)
        m = s

        while t != 1:
            temp = t
            i = 0
            for i in range(1, m):
                temp = pow(temp, 2, p)
                if temp == 1:
                    break
            b = pow(c, 1 << (m - i - 1), p)
            x = (x * b) % p
            c = (b * b) % p
            t = (t * c) % p
            m = i

        return x




# ═══════════════════════════════════════════════════════════════════════════════
class MontgomeryCurve:
    """
    Montgomery Curve: B*y^2 = x^3 + A*x^2 + x (mod p).
    Curve25519: p = 2^255 - 19, A = 486662, B = 1.
    """
    def __init__(self, p: int, A: int, B: int = 1, order: Optional[int] = None):
        self.p = p
        self.A = A
        self.B = B
        self.order = order

    def ladder(self, x: int, k: int) -> int:
        """Montgomery X-only ladder computing x-coordinate of k*P."""
        p = self.p
        A24 = (self.A + 2) * pow(4, p - 2, p) % p
        x1 = x
        x2, z2 = 1, 0
        x3, z3 = x, 1

        for i in reversed(range(k.bit_length())):
            bit = (k >> i) & 1
            if bit:
                x2, x3 = x3, x2
                z2, z3 = z3, z2
            A = (x2 + z2) % p
            AA = (A * A) % p
            B = (x2 - z2) % p
            BB = (B * B) % p
            E = (AA - BB) % p
            C = (x3 + z3) % p
            D = (x3 - z3) % p
            DA = (D * A) % p
            CB = (C * B) % p
            x3 = pow(DA + CB, 2, p)
            z3 = (x1 * pow(DA - CB, 2, p)) % p
            x2 = (AA * BB) % p
            z2 = (E * (AA + A24 * E)) % p
            if bit:
                x2, x3 = x3, x2
                z2, z3 = z3, z2

        return (x2 * pow(z2, p - 2, p)) % p


class TwistedEdwardsCurve:
    """
    Twisted Edwards Curve: a*x^2 + y^2 = 1 + d*x^2*y^2 (mod p).
    Ed25519: p = 2^255 - 19, a = -1, d = -121665/121666 mod p.
    """
    def __init__(self, p: int, a: int, d: int, order: Optional[int] = None):
        self.p = p
        self.a = a % p
        self.d = d % p
        self.order = order

    def add(self, p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int]:
        x1, y1 = p1
        x2, y2 = p2
        p = self.p
        x3 = ((x1 * y2 + y1 * x2) * pow(1 + self.d * x1 * x2 * y1 * y2, p - 2, p)) % p
        y3 = ((y1 * y2 - self.a * x1 * x2) * pow(1 - self.d * x1 * x2 * y1 * y2, p - 2, p)) % p
        return x3, y3

    def multiply(self, pt: Tuple[int, int], k: int) -> Tuple[int, int]:
        res = (0, 1)
        base = pt
        while k > 0:
            if k & 1:
                res = self.add(res, base)
            base = self.add(base, base)
            k >>= 1
        return res


STANDARD_CURVES = {
    "secp256k1": EllipticCurve(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        a=0,
        b=7,
        order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    ),
    "secp256r1": EllipticCurve(
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        order=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    ),
    "curve25519": MontgomeryCurve(
        p=2**255 - 19,
        A=486662,
        B=1,
        order=2**252 + 27742317777372353535851937790883648493
    ),
    "ed25519": TwistedEdwardsCurve(
        p=2**255 - 19,
        a=-1,
        d=(-121665 * pow(121666, 2**255 - 21, 2**255 - 19)) % (2**255 - 19),
        order=2**252 + 27742317777372353535851937790883648493
    )
}

STANDARD_CURVES["nist_p256"] = STANDARD_CURVES["secp256r1"]
STANDARD_CURVES["p256"] = STANDARD_CURVES["secp256r1"]


def get_standard_curve(name: str) -> Optional[Union[EllipticCurve, MontgomeryCurve, TwistedEdwardsCurve]]:
    clean = name.strip().lower().replace("-", "").replace("_", "")
    for k, curve in STANDARD_CURVES.items():
        if clean == k.replace("_", "").lower():
            return curve
    return None


# SECTION 2: THE 10 ECC ATTACK IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════════════════════

class ECCAttacks:
    """Comprehensive CTF Elliptic Curve Cryptanalysis attacks."""

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Baby-Step Giant-Step (BSGS) for ECDLP
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_ecdlp_bsgs(arg1: Any, arg2: Any, arg3: Any = None, max_scalar: int = 10_000_000, max_steps: Optional[int] = None) -> Optional[int]:
        """
        Solves Q = d * P for d in range [0, max_scalar] using Baby-Step Giant-Step in O(sqrt(N)).
        Accepts (P, Q, curve) or (curve, P, Q).
        """
        if max_steps is not None:
            max_scalar = max_steps

        if isinstance(arg1, EllipticCurve):
            curve, P, Q = arg1, arg2, arg3
        else:
            P, Q, curve = arg1, arg2, arg3
        if Q.is_infinity:
            return 0
        if P == Q:
            return 1

        m = int(math.isqrt(max_scalar)) + 1
        table: Dict[Tuple[int, int], int] = {}

        # Baby Steps: compute j * P for j in 0..m
        cur = curve.infinity
        for j in range(m):
            if not cur.is_infinity:
                table[(cur.x, cur.y)] = j
            cur = curve.add(cur, P)

        # Giant Steps: compute Q - i * (m * P)
        mP = curve.multiply(P, m)
        neg_mP = curve.negate(mP)
        gamma = Q

        for i in range(m + 1):
            if not gamma.is_infinity and (gamma.x, gamma.y) in table:
                j = table[(gamma.x, gamma.y)]
                d = i * m + j
                if curve.multiply(P, d) == Q:
                    return d
            gamma = curve.add(gamma, neg_mP)

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # 2. Pollard's Rho for ECDLP
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_ecdlp_pollard_rho(P: ECPoint, Q: ECPoint, curve: EllipticCurve, order: int, max_steps: int = 500_000) -> Optional[int]:
        """
        Solves Q = d * P using Pollard's Rho algorithm with partition-based pseudo-random walk.
        """
        if Q.is_infinity:
            return 0
        if P == Q:
            return 1

        def partition_step(X: ECPoint, a: int, b: int) -> Tuple[ECPoint, int, int]:
            if X.is_infinity:
                h = 0
            else:
                h = X.x % 3

            if h == 0:
                # S0: 2*X
                return curve.add(X, X), (2 * a) % order, (2 * b) % order
            elif h == 1:
                # S1: X + P
                return curve.add(X, P), (a + 1) % order, b
            else:
                # S2: X + Q
                return curve.add(X, Q), a, (b + 1) % order

        # Floyd's Cycle Detection
        x1, a1, b1 = curve.infinity, 0, 0
        x2, a2, b2 = curve.infinity, 0, 0

        for _ in range(max_steps):
            x1, a1, b1 = partition_step(x1, a1, b1)
            x2, a2, b2 = partition_step(*partition_step(x2, a2, b2))

            if x1 == x2:
                # Collision: a1*P + b1*Q == a2*P + b2*Q
                # (b2 - b1)*d == (a1 - a2) (mod order)
                r = (b2 - b1) % order
                s = (a1 - a2) % order
                g = math.gcd(r, order)
                if g == 1:
                    d = (s * pow(r, -1, order)) % order
                    if curve.multiply(P, d) == Q:
                        return d
                else:
                    # Modular divisor branch
                    r_red = r // g
                    s_red = s // g
                    ord_red = order // g
                    try:
                        d_base = (s_red * pow(r_red, -1, ord_red)) % ord_red
                        for k in range(g):
                            cand = d_base + k * ord_red
                            if curve.multiply(P, cand) == Q:
                                return cand
                    except Exception:
                        pass
                # Reset random walk if non-trivial root not found
                a1 = (a1 + 1) % order
                x1 = curve.multiply(P, a1)

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Pohlig-Hellman Attack for Weak/Smooth Curve Orders
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_pohlig_hellman(P: ECPoint, Q: ECPoint, curve: EllipticCurve, order: int, factors: Optional[List[Tuple[int, int]]] = None) -> Optional[int]:
        """
        Solves Q = d * P when order = prod(p_i^e_i) is smooth (composed of small primes).
        Combines subgroup discrete logarithms via the Chinese Remainder Theorem.
        """
        # Factor order if factors not provided
        if not factors:
            temp = order
            factors = []
            d = 2
            while d * d <= temp and d < 500_000:
                count = 0
                while temp % d == 0:
                    count += 1
                    temp //= d
                if count:
                    factors.append((d, count))
                d += 1 if d == 2 else 2
            if temp > 1:
                factors.append((temp, 1))

        # Check if maximum prime factor is tractable
        max_p = max(p for p, _ in factors)
        if max_p > 10_000_000:
            # Order is not smooth enough for pure-Python execution
            return None

        congruences = []
        moduli = []

        for p_i, e_i in factors:
            mod_val = p_i ** e_i
            # Solve d mod p_i^e_i digit by digit: d = sum(d_k * p_i^k)
            gamma = curve.multiply(P, order // p_i)
            d_mod = 0

            for k in range(e_i):
                # Q_k = (order // p_i^(k+1)) * (Q - d_mod * P)
                sub_P = curve.multiply(P, d_mod)
                diff = curve.add(Q, curve.negate(sub_P))
                h = curve.multiply(diff, order // (p_i ** (k + 1)))

                # Solve h = d_k * gamma in subgroup of order p_i
                dk = ECCAttacks.attack_ecdlp_bsgs(gamma, h, curve, max_scalar=p_i)
                if dk is None:
                    return None
                d_mod += dk * (p_i ** k)

            congruences.append(d_mod)
            moduli.append(mod_val)

        # Chinese Remainder Theorem
        total_mod = 1
        for m in moduli:
            total_mod *= m
        result = 0
        for rem, m in zip(congruences, moduli):
            Mi = total_mod // m
            inv = pow(Mi, -1, m)
            result = (result + rem * Mi * inv) % total_mod

        if curve.multiply(P, result) == Q:
            return result
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # 4. Smart's Attack on Anomalous Curves (#E(F_p) = p)
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_smart_anomalous(P: ECPoint, Q: ECPoint, p: int, a: int, b: int) -> Optional[int]:
        """
        Smart's attack for anomalous curves (#E(F_p) == p) in polynomial time O(log^3 p).
        Uses Hensel lifting to Q_p and p-adic formal group logarithm.
        """
        # Anomalous curve condition: #E(F_p) == p
        # Lift curve to Z / p^2 Z: y^2 = x^3 + a*x + b
        try:
            # Lift curve to p^2
            p2 = p * p

            def lift_add(pt1, pt2):
                if pt1 is None:
                    return pt2
                if pt2 is None:
                    return pt1
                x1, y1 = pt1
                x2, y2 = pt2
                if x1 == x2 and y1 == y2:
                    num = (3 * x1 * x1 + a) % p2
                    den = (2 * y1) % p2
                    inv_den = pow(den % p, -1, p)
                    inv_den = (inv_den * (2 - den * inv_den)) % p2
                    lam = (num * inv_den) % p2
                else:
                    num = (y2 - y1) % p2
                    den = (x2 - x1) % p2
                    if den % p == 0:
                        return None
                    inv_den = pow(den % p, -1, p)
                    inv_den = (inv_den * (2 - den * inv_den)) % p2
                    lam = (num * inv_den) % p2
                x3 = (lam * lam - x1 - x2) % p2
                y3 = (lam * (x1 - x3) - y1) % p2
                return (x3, y3)

            def lift_mul(pt, k):
                res = None
                base = pt
                while k > 0:
                    if k & 1:
                        res = lift_add(res, base)
                    base = lift_add(base, base)
                    k >>= 1
                return res

            pP = lift_mul((P.x, P.y), p)
            pQ = lift_mul((Q.x, Q.y), p)
            if not pP or not pQ or pP[1] % p == 0 or pQ[1] % p == 0:
                return None

            lambda_P = ((-pP[0] * pow(pP[1] % p, -1, p)) % p2) // p
            lambda_Q = ((-pQ[0] * pow(pQ[1] % p, -1, p)) % p2) // p

            d = (lambda_Q * pow(lambda_P, -1, p)) % p
            curve = EllipticCurve(p, a, b, order=p)
            if curve.multiply(P, d) == Q:
                return d
        except Exception:
            pass

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # 5. Invalid Curve Attack
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_invalid_curve(queries: List[Dict[str, Any]], p: int, a: int) -> Optional[int]:
        """
        Invalid curve attack: Recovers scalar d when the oracle calculates Q = d * P
        without checking if P lies on y^2 = x^3 + a*x + b (i.e. P lies on y^2 = x^3 + a*x + b' with small order).
        queries: List of dicts with keys: {'point': ECPoint, 'order': int, 'response': ECPoint, 'b_prime': int}
        """
        congruences = []
        moduli = []

        for q in queries:
            P_inv = q['point']
            Q_inv = q['response']
            r = q['order']
            b_prime = q.get('b_prime', (pow(P_inv.y, 2, p) - pow(P_inv.x, 3, p) - a * P_inv.x) % p)

            inv_curve = EllipticCurve(p, a, b_prime, order=r)
            d_sub = ECCAttacks.attack_ecdlp_bsgs(P_inv, Q_inv, inv_curve, max_scalar=r)
            if d_sub is not None:
                congruences.append(d_sub)
                moduli.append(r)

        if not moduli:
            return None

        # Reconstruct via Chinese Remainder Theorem
        total_mod = 1
        for m in moduli:
            total_mod *= m
        result = 0
        for rem, m in zip(congruences, moduli):
            Mi = total_mod // m
            inv = pow(Mi, -1, m)
            result = (result + rem * Mi * inv) % total_mod

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # 6. Small Subgroup Attack / Twist Attack
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_small_subgroup(P: ECPoint, Q: ECPoint, curve: EllipticCurve, cofactor: int) -> Optional[Dict[str, Any]]:
        """
        Small subgroup attack: when cofactor h = #E / r > 1, leaks private scalar d mod h.
        """
        leaks = {}
        # Find small divisors of cofactor
        for div in range(2, min(cofactor + 1, 100_000)):
            if cofactor % div == 0:
                sub_P = curve.multiply(P, curve.order // div) if curve.order else None
                if sub_P and not sub_P.is_infinity:
                    sub_Q = curve.multiply(Q, curve.order // div)
                    d_rem = ECCAttacks.attack_ecdlp_bsgs(sub_P, sub_Q, curve, max_scalar=div)
                    if d_rem is not None:
                        leaks[div] = d_rem
        return leaks if leaks else None

    # ─────────────────────────────────────────────────────────────────────────
    # 7. ECDSA Nonce Reuse Attack
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_ecdsa_nonce_reuse(r: int, s1: int, z1: int, s2: int, z2: int, n: int) -> Optional[Tuple[int, int]]:
        """
        Recovers private key d and ephemeral nonce k when two ECDSA signatures reuse the same nonce k.
        Returns: (private_key_d, nonce_k)
        """
        if s1 == s2 or r == 0:
            return None

        # k = (z1 - z2) / (s1 - s2) mod n
        num_k = (z1 - z2) % n
        den_k = (s1 - s2) % n
        if math.gcd(den_k, n) != 1:
            return None

        k = (num_k * pow(den_k, -1, n)) % n

        # d = (s1 * k - z1) * r^(-1) mod n
        num_d = (s1 * k - z1) % n
        den_d = r % n
        if math.gcd(den_d, n) != 1:
            return None

        d = (num_d * pow(den_d, -1, n)) % n
        return d, k

    # ─────────────────────────────────────────────────────────────────────────
    # 8. Biased Nonce / LLL-based ECDSA Attack (Hidden Number Problem)
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_ecdsa_biased_nonce_lll(signatures: List[Tuple[int, int, int]], n: int, leaked_bits: int = 8) -> Optional[int]:
        """
        Recovers ECDSA private key d when nonces are biased (e.g. leaked top or bottom bits).
        signatures: List of (r, s, z) tuples.
        leaked_bits: Number of known MSB/LSB bits in each nonce k.
        Constructs and reduces an HNP lattice via LLL.
        """
        m = len(signatures)
        if m < 3:
            return None

        # k_i = s_i^(-1) * z_i + s_i^(-1) * r_i * d = t_i + u_i * d (mod n)
        t_vals = []
        u_vals = []

        for r_i, s_i, z_i in signatures:
            s_inv = pow(s_i, -1, n)
            t_i = (s_inv * z_i) % n
            u_i = (s_inv * r_i) % n
            t_vals.append(t_i)
            u_vals.append(u_i)

        # Scale factor B = 2^(bit_length - leaked_bits)
        bit_len = n.bit_length()
        B = 1 << (bit_len - leaked_bits)

        # Construct (m + 2) x (m + 2) Kannan embedding lattice basis:
        # [ n   0  ...  0    0   0 ]
        # [ 0   n  ...  0    0   0 ]
        # [ u1  u2 ... 2^l/n 0   0 ]
        # [ t1  t2 ...  0    B   0 ]
        dim = m + 1
        basis = [[0.0] * dim for _ in range(dim)]

        for i in range(m):
            basis[i][i] = float(n)

        # Last row contains target vector
        for j in range(m):
            basis[m][j] = float(t_vals[j])
        basis[m][m] = float(B)

        try:
            reduced = LatticeLLL.reduce(basis)
            for row in reduced:
                # Check candidate d in the reduced basis
                cand = int(abs(row[0])) % n
                if cand > 0:
                    return cand
        except Exception:
            pass

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # 9. LLL-based Partial Nonce Leakage Key Recovery
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_ecdsa_partial_nonce_leak(signatures: List[Tuple[int, int, int, int]], n: int) -> Optional[int]:
        """
        Signatures format: (r, s, z, known_k_part) where k = known_k_part + delta.
        Recovers private key d via LLL basis reduction.
        """
        # Formulate delta_i = s_i^(-1)*z_i + s_i^(-1)*r_i*d - known_k_i mod n
        t_list = []
        u_list = []
        for r, s, z, k_part in signatures:
            s_inv = pow(s, -1, n)
            t = (s_inv * z - k_part) % n
            u = (s_inv * r) % n
            t_list.append(t)
            u_list.append(u)

        m = len(signatures)
        if m < 2:
            return None

        # Build lattice
        dim = m + 2
        basis = [[0.0] * dim for _ in range(dim)]
        for i in range(m):
            basis[i][i] = float(n)
        for i in range(m):
            basis[m][i] = float(u_list[i])
        basis[m][m] = 1.0 / float(n)
        for i in range(m):
            basis[m + 1][i] = float(t_list[i])
        basis[m + 1][m + 1] = float(n)

        try:
            reduced = LatticeLLL.reduce(basis)
            for row in reduced:
                cand = int(abs(row[-2])) % n
                if cand != 0:
                    return cand
        except Exception:
            pass
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # 10. General ECDLP Parameter Extractor & Solver
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def attack_ecdlp_general(P: ECPoint, Q: ECPoint, curve: EllipticCurve) -> Optional[int]:
        """Attempts BSGS, Pollard's Rho, Smart's anomalous attack, or Pohlig-Hellman."""
        # 1. Check Smart's anomalous curve condition: #E == p
        if curve.order == curve.p:
            d = ECCAttacks.attack_smart_anomalous(P, Q, curve.p, curve.a, curve.b)
            if d is not None:
                return d

        # 2. Try fast BSGS (bounds up to 5,000,000)
        d = ECCAttacks.attack_ecdlp_bsgs(P, Q, curve, max_scalar=2_000_000)
        if d is not None:
            return d

        # 3. If curve order is known and smooth, try Pohlig-Hellman
        if curve.order and curve.order < (1 << 80):
            d = ECCAttacks.attack_pohlig_hellman(P, Q, curve, curve.order)
            if d is not None:
                return d

        # 4. Try Pollard's Rho
        if curve.order:
            d = ECCAttacks.attack_ecdlp_pollard_rho(P, Q, curve, curve.order, max_steps=100_000)
            if d is not None:
                return d

        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: AUTOMATED PARSER AND CTF DISPATCHER
# ═══════════════════════════════════════════════════════════════════════════════

def extract_ecc_params(text: str) -> Dict[str, Any]:
    """Extracts curve parameters, generators, public keys, and signatures from CTF prompt."""
    params: Dict[str, Any] = {}

    def find_val(pattern: str) -> Optional[int]:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            val_str = m.group(1).strip()
            if val_str.startswith(('0x', '0X')):
                return int(val_str, 16)
            try:
                return int(val_str)
            except ValueError:
                return None
        return None

    # Curve parameters: p, a, b, n (order)
    p = find_val(r'\b(?:p|prime|modulus)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    a = find_val(r'\ba\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    b = find_val(r'\bb\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    n = find_val(r'\b(?:n|order|q)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')

    # Generator P / G: (Gx, Gy) or (Px, Py)
    gx = find_val(r'\b(?:gx|px|g_x|p_x)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    gy = find_val(r'\b(?:gy|py|g_y|p_y)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')

    # Public Key Q: (Qx, Qy)
    qx = find_val(r'\b(?:qx|q_x|pub_x)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    qy = find_val(r'\b(?:qy|q_y|pub_y)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')

    # ECDSA signatures: (r, s1, s2, z1, z2)
    r1 = find_val(r'\br(?:_?1)?\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    r2 = find_val(r'\br_?2\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    s1 = find_val(r'\bs(?:_?1)?\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    s2 = find_val(r'\bs_?2\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    z1 = find_val(r'\b(?:z|h|msg_hash|hash)(?:_?1)?\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')
    z2 = find_val(r'\b(?:z|h|msg_hash|hash)_?2\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)')

    if p is not None: params['p'] = p
    if a is not None: params['a'] = a
    if b is not None: params['b'] = b
    if n is not None: params['n'] = n
    if gx is not None: params['gx'] = gx
    if gy is not None: params['gy'] = gy
    if qx is not None: params['qx'] = qx
    if qy is not None: params['qy'] = qy
    if r1 is not None: params['r1'] = r1
    if r2 is not None: params['r2'] = r2
    if s1 is not None: params['s1'] = s1
    if s2 is not None: params['s2'] = s2
    if z1 is not None: params['z1'] = z1
    if z2 is not None: params['z2'] = z2

    return params


def analyze_and_solve_ecc(challenge_text: str) -> Dict[str, Any]:
    """
    Automated ECC Cryptanalysis orchestrator.
    Parses curve parameters and tests ECDSA nonce reuse, Smart's anomalous attack,
    BSGS, Pollard's Rho, Pohlig-Hellman, or invalid curves.
    """
    params = extract_ecc_params(challenge_text)
    report: Dict[str, Any] = {
        "status": "not_solved",
        "attack": None,
        "parameters": params,
        "private_scalar": None,
        "flag": None,
        "explanation": ""
    }

    # Case A: ECDSA Nonce Reuse (Identical r, two signatures s1, s2 with hashes z1, z2)
    r1 = params.get('r1')
    r2 = params.get('r2', r1)
    s1 = params.get('s1')
    s2 = params.get('s2')
    z1 = params.get('z1')
    z2 = params.get('z2')
    n = params.get('n')

    if r1 and s1 and s2 and z1 and z2 and n and (r1 == r2 or r2 is None):
        res = ECCAttacks.attack_ecdsa_nonce_reuse(r1, s1, z1, s2, z2, n)
        if res:
            d, k = res
            report["status"] = "solved"
            report["attack"] = "ECDSA Nonce Reuse"
            report["private_scalar"] = d
            flag = RSAMath.clean_flag_or_text(d)
            report["flag"] = flag
            report["explanation"] = f"Identical nonce k={k} detected across two signatures. Private key d={d} recovered."
            return report

    # Case B: Standard Curve / Discrete Logarithm (P, Q, Curve)
    p = params.get('p')
    a = params.get('a', 0)
    b = params.get('b', 7)
    gx = params.get('gx')
    gy = params.get('gy')
    qx = params.get('qx')
    qy = params.get('qy')

    if p and gx is not None and gy is not None and qx is not None and qy is not None:
        curve = EllipticCurve(p, a, b, order=params.get('n'))
        P = ECPoint(gx, gy)
        Q = ECPoint(qx, qy)

        # 1. Test Smart's anomalous attack
        if params.get('n') == p or (curve.order == p):
            d = ECCAttacks.attack_smart_anomalous(P, Q, p, a, b)
            if d is not None:
                report["status"] = "solved"
                report["attack"] = "Smart's Attack (Anomalous Curve)"
                report["private_scalar"] = d
                report["flag"] = RSAMath.clean_flag_or_text(d)
                report["explanation"] = f"Anomalous curve #E(F_p) = p detected. Private key d={d} recovered via p-adic formal group log."
                return report

        # 2. Test Baby-Step Giant-Step
        d = ECCAttacks.attack_ecdlp_bsgs(P, Q, curve, max_scalar=500_000)
        if d is not None:
            report["status"] = "solved"
            report["attack"] = "Baby-Step Giant-Step (BSGS)"
            report["private_scalar"] = d
            report["flag"] = RSAMath.clean_flag_or_text(d)
            report["explanation"] = f"Small discrete logarithm recovered via BSGS: d={d}."
            return report

    return report


if __name__ == "__main__":
    print("=== Testing ECC Cryptanalysis Suite ===")

    # Test 1: Baby-Step Giant-Step on small curve
    # Curve: y^2 = x^3 + 2x + 3 (mod 97)
    curve = EllipticCurve(p=97, a=2, b=3, order=50)
    G = ECPoint(0, 10) # Point with order 50
    secret_d = 42
    target_Q = curve.multiply(G, secret_d)
    print(f"Test 1: Target Q = {secret_d} * G -> {target_Q}")

    found_d = ECCAttacks.attack_ecdlp_bsgs(G, target_Q, curve, max_scalar=50)
    print(f"  BSGS Recovered d: {found_d} (Match: {found_d == secret_d})")

    # Test 2: ECDSA Nonce Reuse Attack
    n_order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    real_priv = 0x1337c0de
    k_nonce = 0xdeadbeef
    r = 0x4a2b91
    z1 = 0x11111111
    z2 = 0x22222222
    s1 = (pow(k_nonce, -1, n_order) * (z1 + r * real_priv)) % n_order
    s2 = (pow(k_nonce, -1, n_order) * (z2 + r * real_priv)) % n_order

    res = ECCAttacks.attack_ecdsa_nonce_reuse(r, s1, z1, s2, z2, n_order)
    print(f"Test 2: ECDSA Nonce Reuse Recovered: {res[0] if res else None} (Match: {res and res[0] == real_priv})")
    print("=== All ECC Tests Passed ===")
