with open('ecc_cryptanalysis.py', 'r', encoding='utf-8') as f:
    text = f.read()

marker = "class MontgomeryCurve:"
end_marker = "return None\n\n\n"

# Remove all instances of the added block
while marker in text:
    idx = text.find(marker)
    # find end of block which is "return None\n"
    end_idx = text.find("return None\n", idx)
    if end_idx != -1:
        text = text[:idx] + text[end_idx + len("return None\n"):]
    else:
        break

addition = '''class MontgomeryCurve:
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
'''

sec2 = "# SECTION 2: THE 10 ECC ATTACK IMPLEMENTATIONS"
text = text.replace(sec2, addition + "\n\n" + sec2)

with open('ecc_cryptanalysis.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("ecc_cryptanalysis.py cleaned and updated!")
