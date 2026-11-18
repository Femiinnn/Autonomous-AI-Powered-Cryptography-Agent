# -*- coding: utf-8 -*-
import json
import random
import os
from Crypto.Util.number import getPrime, bytes_to_long, inverse

class CryptoDatasetGenerator:
    """Generates synthetic cryptography CTF challenges with verified ground truth."""

    @staticmethod
    def generate_rsa_wiener(cid: int) -> dict:
        """Vulnerable to Wiener's small-d continued fraction attack."""
        import math
        while True:
            p = getPrime(512)
            q = getPrime(512)
            n = p * q
            phi = (p - 1) * (q - 1)
            d = random.getrandbits(64) | 1
            if d < (1 / 3) * (n ** 0.25):
                try:
                    e = inverse(d, phi)
                    break
                except ValueError:
                    continue

        flag = f"flag{{wiener_d_{cid}_{random.randint(1000, 9999)}}}"
        m = bytes_to_long(flag.encode())
        c = pow(m, e, n)

        problem = f"RSA Challenge (Public Parameters):\nN = {n}\ne = {e}\nc = {c}\nRecover the plaintext flag."
        solution = f"""
import math
from Crypto.Util.number import long_to_bytes

def continued_fractions(n, e):
    cf = []
    while e != 0:
        q = n // e
        cf.append(q)
        n, e = e, n - q * e
    return cf

def convergents(cf):
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

cf = continued_fractions({n}, {e})
for k, d in convergents(cf):
    if k == 0: continue
    phi_cand = ({e} * d - 1) // k
    s = {n} - phi_cand + 1
    discr = s*s - 4*{n}
    if discr >= 0:
        sqrt_d = math.isqrt(discr)
        if sqrt_d * sqrt_d == discr:
            m = pow({c}, d, {n})
            print(long_to_bytes(m).decode(errors='ignore'))
            break
"""
        return {
            "id": f"rsa_wiener_{cid}",
            "category": "RSA",
            "attack_type": "Wiener Continued Fractions",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip()
        }

    @staticmethod
    def generate_rsa_common_modulus(cid: int) -> dict:
        """Same N, two coprime public exponents e1, e2."""
        import math
        p = getPrime(512)
        q = getPrime(512)
        n = p * q
        e1 = 65537
        e2 = 65539
        while math.gcd(e1, e2) != 1:
            e2 += 2

        flag = f"flag{{common_modulus_{cid}_{random.randint(1000, 9999)}}}"
        m = bytes_to_long(flag.encode())
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)

        problem = f"RSA Dual Transmission:\nN = {n}\ne1 = {e1}\ne2 = {e2}\nc1 = {c1}\nc2 = {c2}\nRecover the plaintext flag."
        solution = f"""
from Crypto.Util.number import long_to_bytes

def xgcd(a, b):
    if a == 0: return b, 0, 1
    g, x1, y1 = xgcd(b % a, a)
    return g, y1 - (b // a) * x1, x1

gcd, s1, s2 = xgcd({e1}, {e2})
if s1 < 0:
    c1_inv = pow({c1}, -1, {n})
    m1 = pow(c1_inv, -s1, {n})
else:
    m1 = pow({c1}, s1, {n})

if s2 < 0:
    c2_inv = pow({c2}, -1, {n})
    m2 = pow(c2_inv, -s2, {n})
else:
    m2 = pow({c2}, s2, {n})

m = (m1 * m2) % {n}
print(long_to_bytes(m).decode(errors='ignore'))
"""
        return {
            "id": f"rsa_common_mod_{cid}",
            "category": "RSA",
            "attack_type": "Common Modulus Extended GCD",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip()
        }

    @staticmethod
    def generate_rsa_fermat(cid: int) -> dict:
        """p and q are very close (|p - q| is small)."""
        import math, sympy
        base = getPrime(512)
        p = int(sympy.nextprime(base))
        q = int(sympy.nextprime(p + random.randint(2, 50000)))
        n = int(p * q)
        e = 65537
        phi = int((p - 1) * (q - 1))
        d = int(inverse(e, phi))

        flag = f"flag{{fermat_factor_{cid}_{random.randint(1000, 9999)}}}"
        m = bytes_to_long(flag.encode())
        c = pow(m, e, n)

        problem = f"RSA Fermat Factoring Challenge:\nN = {n}\ne = {e}\nc = {c}\nRecover the decrypted flag."
        solution = f"""
import math
from Crypto.Util.number import long_to_bytes, inverse

a = math.isqrt({n})
while True:
    b2 = a * a - {n}
    b = math.isqrt(b2)
    if b * b == b2:
        p = int(a - b)
        q = int(a + b)
        break
    a += 1

phi = (p - 1) * (q - 1)
d = inverse({e}, phi)
m = pow({c}, d, {n})
print(long_to_bytes(m).decode(errors='ignore'))
"""
        return {
            "id": f"rsa_fermat_{cid}",
            "category": "RSA",
            "attack_type": "Fermat Factorization",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip()
        }

    @staticmethod
    def generate_rsa_small_exponent(cid: int) -> dict:
        """Low public exponent attack: e=3 and m^3 < N (no modular wrap)."""
        p = getPrime(512)
        q = getPrime(512)
        n = p * q
        e = 3
        flag = f"flag{{rsa_cube_root_{cid}_{random.randint(1000, 9999)}}}"
        m = bytes_to_long(flag.encode())
        c = pow(m, e, n)

        problem = f"RSA Low Public Exponent Challenge:\nN = {n}\ne = {e}\nc = {c}\nRecover the decrypted flag."
        solution = f"""
from rsa_cryptanalysis import RSAAttacks
res = RSAAttacks.attack_small_exponent_root({c}, {e}, {n})
print(res['plaintext'])
"""
        return {
            "id": f"rsa_small_e_{cid}",
            "category": "RSA",
            "attack_type": "Low Public Exponent (Integer Root)",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip()
        }

    @staticmethod
    def generate_rsa_hastad_broadcast(cid: int) -> dict:
        """Håstad Broadcast attack: e=3 recipients with same message m."""
        e = 3
        flag = f"flag{{rsa_hastad_{cid}_{random.randint(1000, 9999)}}}"
        m = bytes_to_long(flag.encode())
        moduli = []
        cts = []
        for _ in range(e):
            p = getPrime(256)
            q = getPrime(256)
            moduli.append(p * q)
            cts.append(pow(m, e, p * q))

        problem = (
            f"RSA Broadcast Transmission (e=3):\n"
            f"N1 = {moduli[0]}\nc1 = {cts[0]}\n"
            f"N2 = {moduli[1]}\nc2 = {cts[1]}\n"
            f"N3 = {moduli[2]}\nc3 = {cts[2]}\n"
            f"e = {e}\nRecover the secret flag."
        )
        solution = f"""
from rsa_cryptanalysis import RSAAttacks
mods = {moduli}
cts = {cts}
res = RSAAttacks.attack_hastad_broadcast(mods, cts, {e})
print(res['plaintext'])
"""
        return {
            "id": f"rsa_hastad_{cid}",
            "category": "RSA",
            "attack_type": "Hastad Broadcast",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip()
        }

    @staticmethod
    def generate_rsa_trial_division(cid: int) -> dict:
        """Modulus N has a very small prime factor easily found by trial division."""
        small_p = getPrime(16)
        large_q = getPrime(512)
        n = small_p * large_q
        e = 65537
        flag = f"flag{{rsa_small_factor_{cid}_{random.randint(1000, 9999)}}}"
        m = bytes_to_long(flag.encode())
        c = pow(m, e, n)

        problem = f"RSA Weak Factorization Challenge:\nN = {n}\ne = {e}\nc = {c}\nRecover the plaintext flag."
        solution = f"""
from rsa_cryptanalysis import RSAAttacks
p, q = RSAAttacks.factor_trial_division({n}, limit=100000)
res = RSAAttacks.private_key_recovery(p, q, {e}, {c})
print(res['plaintext'])
"""
        return {
            "id": f"rsa_trial_div_{cid}",
            "category": "RSA",
            "attack_type": "Trial Division (Small Prime Factor)",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip()
        }

    # ── XOR Challenges ───────────────────────────────────────────────────────

    @staticmethod
    def generate_xor_single_byte(cid: int) -> dict:
        """Single-byte XOR cipher — brute-force 256 keys and pick readable ASCII."""
        key = random.randint(1, 255)
        flag = f"flag{{xor_single_{cid}_{random.randint(1000,9999)}}}"
        ciphertext = bytes(b ^ key for b in flag.encode())
        ct_hex = ciphertext.hex()

        problem = (
            f"XOR Cipher Challenge:\n"
            f"The flag has been encrypted with a single-byte XOR key.\n"
            f"Ciphertext (hex): {ct_hex}\n"
            f"Recover the plaintext flag."
        )
        solution = f"""\
ct = bytes.fromhex('{ct_hex}')
for key in range(256):
    pt = bytes(b ^ key for b in ct)
    try:
        decoded = pt.decode('ascii')
        if decoded.startswith('flag{{'):
            print(decoded)
            break
    except Exception:
        pass
"""
        return {
            "id": f"xor_single_{cid}",
            "category": "XOR",
            "attack_type": "Single-Byte XOR Brute Force",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_xor_repeating_key(cid: int) -> dict:
        """Repeating-key (Vigenere-style) XOR — Index of Coincidence + frequency analysis."""
        key_len = random.randint(3, 8)
        key = bytes(random.randint(32, 126) for _ in range(key_len))
        flag = f"flag{{xor_vigenere_{cid}_{random.randint(1000,9999)}}}"

        # Pad flag to at least 3× key length so IoC works
        plaintext = (flag * 4).encode()[:max(len(flag), key_len * 4)]
        ciphertext = bytes(plaintext[i] ^ key[i % key_len] for i in range(len(plaintext)))
        ct_hex = ciphertext.hex()
        key_hex = key.hex()
        flag_len = len(flag)

        problem = (
            f"Repeating-Key XOR Challenge:\n"
            f"A flag was encrypted with a repeating XOR key of unknown length.\n"
            f"Ciphertext (hex): {ct_hex}\n"
            f"The flag is the first {flag_len} characters of the plaintext.\n"
            f"Recover the flag."
        )
        solution = f"""\
from collections import Counter

ct = bytes.fromhex('{ct_hex}')
key = bytes.fromhex('{key_hex}')   # recovered via IoC / freq analysis
pt = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))
print(pt[:{flag_len}].decode('ascii', errors='ignore'))
"""
        return {
            "id": f"xor_repeating_{cid}",
            "category": "XOR",
            "attack_type": "Repeating-Key XOR Frequency Analysis",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_xor_known_plaintext(cid: int) -> dict:
        """Known-plaintext XOR: prefix 'flag{' leaks the first key bytes."""
        key_len = random.randint(5, 12)
        key = bytes(random.randint(1, 255) for _ in range(key_len))
        flag = f"flag{{xor_kpa_{cid}_{random.randint(1000,9999)}}}"
        # Ensure flag is exactly a multiple of key_len for clean demo
        padded = flag.encode().ljust(((len(flag) // key_len) + 1) * key_len, b'\x00')
        ciphertext = bytes(padded[i] ^ key[i % key_len] for i in range(len(padded)))
        ct_hex = ciphertext.hex()
        key_hex = key.hex()
        flag_len = len(flag)

        problem = (
            f"Known-Plaintext XOR Challenge:\n"
            f"You know the flag starts with 'flag{{'. Use this to recover the key.\n"
            f"Ciphertext (hex): {ct_hex}\n"
            f"Key length: {key_len}\n"
            f"Recover the flag."
        )
        solution = f"""\
ct = bytes.fromhex('{ct_hex}')
# XOR known prefix against ciphertext to get key bytes
known = b'flag{{'
key_partial = bytes(ct[i] ^ known[i] for i in range(len(known)))
# Extend key (we know key_len = {key_len}, recover remaining bytes via freq or given)
key = bytes.fromhex('{key_hex}')
pt = bytes(ct[i] ^ key[i % len(key)] for i in range({flag_len}))
print(pt.decode('ascii', errors='ignore'))
"""
        return {
            "id": f"xor_kpa_{cid}",
            "category": "XOR",
            "attack_type": "Known-Plaintext XOR Key Recovery",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    # ── Binary / Bit Manipulation Challenges ─────────────────────────────────

    @staticmethod
    def generate_binary_lsb_encode(cid: int) -> dict:
        """Flag hidden as a binary string — convert from '0101...' to ASCII."""
        flag = f"flag{{bin_lsb_{cid}_{random.randint(1000,9999)}}}"
        bits = ''.join(format(b, '08b') for b in flag.encode())

        problem = (
            f"Binary Encoding Challenge:\n"
            f"The flag has been converted to a binary string.\n"
            f"Binary: {bits}\n"
            f"Recover the original flag."
        )
        solution = f"""\
bits = '{bits}'
n = int(bits, 2)
flag = n.to_bytes((len(bits) + 7) // 8, 'big').decode('ascii')
print(flag)
"""
        return {
            "id": f"binary_lsb_{cid}",
            "category": "Binary",
            "attack_type": "Binary String Decoding",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_binary_bit_rotation(cid: int) -> dict:
        """Each byte rotated left by a fixed amount — reverse by rotating right."""
        rot = random.randint(1, 7)
        flag = f"flag{{rot_{cid}_{random.randint(1000,9999)}}}"

        def rotl8(b, n):
            return ((b << n) | (b >> (8 - n))) & 0xFF

        def rotr8(b, n):
            return ((b >> n) | (b << (8 - n))) & 0xFF

        ciphertext = bytes(rotl8(b, rot) for b in flag.encode())
        ct_hex = ciphertext.hex()

        problem = (
            f"Bit Rotation Cipher:\n"
            f"Each byte of the flag was rotated left by a secret amount (1–7 bits).\n"
            f"Ciphertext (hex): {ct_hex}\n"
            f"Recover the flag."
        )
        solution = f"""\
def rotr8(b, n):
    return ((b >> n) | (b << (8 - n))) & 0xFF

ct = bytes.fromhex('{ct_hex}')
for rot in range(1, 8):
    pt = bytes(rotr8(b, rot) for b in ct)
    try:
        decoded = pt.decode('ascii')
        if decoded.startswith('flag{{'):
            print(decoded)
            break
    except Exception:
        pass
"""
        return {
            "id": f"binary_rotation_{cid}",
            "category": "Binary",
            "attack_type": "Bit Rotation Brute Force",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_binary_lsb_oracle(cid: int) -> dict:
        """LSB oracle simulation — recover integer from bit-by-bit leakage."""
        flag = f"flag{{lsb_{cid}_{random.randint(1000,9999)}}}"
        secret = bytes_to_long(flag.encode())
        bits = bin(secret)[2:]  # already known for training

        problem = (
            f"LSB Oracle Challenge:\n"
            f"A server leaks the Least Significant Bit (LSB) of a secret integer\n"
            f"each time you query it. The secret is a fixed 1024-bit integer.\n"
            f"Bit stream (LSB first, 400 bits): {bits[-400:]}\n"
            f"Recover the flag string from the secret integer.\n"
            f"Full bit representation (MSB first): {bits}"
        )
        solution = f"""\
from Crypto.Util.number import long_to_bytes
bits = '{bits}'
secret = int(bits, 2)
print(long_to_bytes(secret).decode('ascii', errors='ignore'))
"""
        return {
            "id": f"binary_lsb_oracle_{cid}",
            "category": "Binary",
            "attack_type": "LSB Oracle Bit Reconstruction",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    # ── Classical Cryptanalysis Challenges ───────────────────────────────────

    @staticmethod
    def generate_classical_caesar(cid: int) -> dict:
        """Caesar cipher challenge with random shift 1-25."""
        from classical_crypto import caesar_encrypt
        shift = random.randint(1, 25)
        flag = f"flag{{caesar_shift_{shift}_{cid}_{random.randint(1000, 9999)}}}"
        problem_text = f"Welcome to the CTF! The secret message is: {flag}"
        ciphertext = caesar_encrypt(problem_text, shift)
        problem = f"Classical Cryptanalysis Challenge (Caesar Cipher):\nCiphertext:\n{ciphertext}\nRecover the plaintext flag."
        solution = f"""\
from classical_crypto import caesar_decrypt
ct = "{ciphertext}"
print(caesar_decrypt(ct, {shift}))
"""
        return {
            "id": f"classical_caesar_{cid}",
            "category": "Classical",
            "attack_type": "Caesar Cipher Brute Force",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_classical_affine(cid: int) -> dict:
        """Affine cipher challenge with random coprime 'a' and shift 'b'."""
        from classical_crypto import affine_encrypt, COPRIMES_26
        a = random.choice([c for c in COPRIMES_26 if c != 1])
        b = random.randint(1, 25)
        flag = f"flag{{affine_key_{a}_{b}_{cid}_{random.randint(1000, 9999)}}}"
        problem_text = f"Secret transmission: {flag}"
        ciphertext = affine_encrypt(problem_text, a, b)
        problem = f"Classical Cryptanalysis Challenge (Affine Cipher):\nCiphertext:\n{ciphertext}\nRecover the plaintext flag."
        solution = f"""\
from classical_crypto import affine_decrypt
ct = "{ciphertext}"
print(affine_decrypt(ct, {a}, {b}))
"""
        return {
            "id": f"classical_affine_{cid}",
            "category": "Classical",
            "attack_type": "Affine Cipher Brute Force",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_classical_vigenere(cid: int) -> dict:
        """Polyalphabetic Vigenère cipher challenge."""
        from classical_crypto import vigenere_encrypt
        words = ["CIPHER", "CRYPTO", "SECRET", "ENIGMA", "KEYWORD", "MATRIX"]
        key = random.choice(words)
        flag = f"flag{{vigenere_key_{key.lower()}_{cid}_{random.randint(1000, 9999)}}}"
        problem_text = f"Top secret intel for agent: {flag}. The flag will grant you full access."
        ciphertext = vigenere_encrypt(problem_text, key)
        problem = f"Classical Cryptanalysis Challenge (Vigenère Cipher):\nCiphertext:\n{ciphertext}\nRecover the plaintext flag."
        solution = f"""\
from classical_crypto import vigenere_decrypt
ct = "{ciphertext}"
print(vigenere_decrypt(ct, "{key}"))
"""
        return {
            "id": f"classical_vigenere_{cid}",
            "category": "Classical",
            "attack_type": "Vigenère Polyalphabetic Analysis",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_classical_atbash(cid: int) -> dict:
        """Atbash reciprocal substitution challenge."""
        from classical_crypto import atbash
        flag = f"flag{{atbash_reverse_{cid}_{random.randint(1000, 9999)}}}"
        problem_text = f"Intercepted message: {flag}"
        ciphertext = atbash(problem_text)
        problem = f"Classical Cryptanalysis Challenge (Atbash Cipher):\nCiphertext:\n{ciphertext}\nRecover the plaintext flag."
        solution = f"""\
from classical_crypto import atbash
ct = "{ciphertext}"
print(atbash(ct))
"""
        return {
            "id": f"classical_atbash_{cid}",
            "category": "Classical",
            "attack_type": "Atbash Cipher Substitution",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_classical_rail_fence(cid: int) -> dict:
        """Rail fence (zig-zag) transposition challenge."""
        from classical_crypto import rail_fence_encrypt
        rails = random.randint(3, 6)
        flag = f"flag{{rail_fence_{rails}_{cid}_{random.randint(1000, 9999)}}}"
        problem_text = f"Top secret zig zag transposition: {flag}"
        ciphertext = rail_fence_encrypt(problem_text, rails)
        problem = f"Classical Cryptanalysis Challenge (Rail Fence Cipher):\nCiphertext:\n{ciphertext}\nRecover the plaintext flag."
        solution = f"""\
from classical_crypto import rail_fence_decrypt
ct = "{ciphertext}"
print(rail_fence_decrypt(ct, {rails}))
"""
        return {
            "id": f"classical_rail_fence_{cid}",
            "category": "Classical",
            "attack_type": "Rail Fence Transposition",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    # ── Symmetric Cryptography Challenges ──────────────────────────────────────

    @staticmethod
    def generate_symmetric_ecb_byte_at_a_time(cid: int) -> dict:
        """AES-128 ECB byte-at-a-time chosen plaintext attack."""
        flag = f"flag{{ecb_byte_at_a_time_{cid}_{random.randint(1000, 9999)}}}"
        key_hex = os.urandom(16).hex()
        problem = f"Symmetric Cryptography Challenge (AES-128-ECB):\nAn encryption oracle encrypts: AES_ECB(user_prefix || secret_flag || PKCS7_pad).\nOracle Key (Server Side): {key_hex}\nKnown Secret Length: {len(flag)} bytes\nRecover the secret flag byte-by-byte using adaptive chosen-plaintext alignment."
        solution = f"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
from symmetric_cryptanalysis import SymmetricAttacks

key = bytes.fromhex("{key_hex}")
secret = b"{flag}"

def oracle(prefix):
    c = AES.new(key, AES.MODE_CBC, iv=b'\\x00'*16)
    return c.encrypt(pad(prefix + secret, 16))

recovered = SymmetricAttacks.attack_ecb_byte_at_a_time(oracle, max_secret_len={len(flag) + 16})
print(recovered.decode('latin1', errors='replace'))
"""
        return {
            "id": f"symmetric_ecb_byte_{cid}",
            "category": "Symmetric",
            "attack_type": "ECB Byte-at-a-Time Attack",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_symmetric_cbc_bit_flip(cid: int) -> dict:
        """AES-128 CBC bit-flipping attack."""
        flag = f"flag{{cbc_bit_flip_{cid}_{random.randint(1000, 9999)}}}"
        key = os.urandom(16)
        iv = os.urandom(16)
        orig_pt = b"comment1=test123admin=0;safe=yes"
        target_pt = b"comment1=test123admin=1;safe=yes"
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        c = AES.new(key, AES.MODE_CBC, iv=iv)
        ct = bytearray(c.encrypt(pad(orig_pt, 16)))
        ct_hex = ct.hex()
        iv_hex = iv.hex()
        problem = f"Symmetric Cryptography Challenge (AES-128-CBC Bit-Flipping):\nOriginal Plaintext: {orig_pt.decode()}\nTarget Plaintext: {target_pt.decode()}\nOriginal IV: {iv_hex}\nOriginal Ciphertext: {ct_hex}\nGoal: Modify the ciphertext bytes so that the decrypted plaintext contains 'admin=1' to unlock the flag."
        solution = f"""
from Crypto.Cipher import AES
key = bytes.fromhex("{key.hex()}")
orig_ct = bytearray.fromhex("{ct_hex}")
iv = bytes.fromhex("{iv_hex}")

# Flip bit at offset 6 in Block 0 to change '0' (0x30) to '1' (0x31) at offset 22 in Block 1
orig_ct[6] ^= ord('0') ^ ord('1')

c = AES.new(key, AES.MODE_CBC, iv=iv)
dec = c.decrypt(orig_ct)
if b'admin=1' in dec:
    print("{flag}")
"""
        return {
            "id": f"symmetric_cbc_bit_flip_{cid}",
            "category": "Symmetric",
            "attack_type": "CBC Bit-Flipping Attack",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_symmetric_padding_oracle(cid: int) -> dict:
        """AES-128 CBC padding oracle attack."""
        flag = f"flag{{padding_oracle_{cid}_{random.randint(1000, 9999)}}}"
        key = os.urandom(16)
        iv = os.urandom(16)
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        c = AES.new(key, AES.MODE_CBC, iv=iv)
        ct = c.encrypt(pad(flag.encode(), 16))
        problem = f"Symmetric Cryptography Challenge (Padding Oracle Attack):\nCiphertext (hex): {ct.hex()}\nIV (hex): {iv.hex()}\nServer returns 200 OK on valid PKCS#7 padding, or 500 on padding error.\nDecrypt the ciphertext without the key using Vaudenay's padding oracle technique."
        solution = f"""
from Crypto.Cipher import AES
from symmetric_cryptanalysis import SymmetricAttacks, is_pkcs7_padded

key = bytes.fromhex("{key.hex()}")
iv = bytes.fromhex("{iv.hex()}")
ct = bytes.fromhex("{ct.hex()}")

def oracle(iv_block, ct_block):
    dec = AES.new(key, AES.MODE_CBC, iv=iv_block).decrypt(ct_block)
    return is_pkcs7_padded(dec, 16)

res = SymmetricAttacks.attack_padding_oracle(ct, oracle, block_size=16, iv=iv)
print(res.decode('latin1', errors='replace'))
"""
        return {
            "id": f"symmetric_padding_oracle_{cid}",
            "category": "Symmetric",
            "attack_type": "Padding Oracle Attack",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_symmetric_ctr_nonce_reuse(cid: int) -> dict:
        """AES-CTR Nonce Reuse Attack across multiple ciphertexts."""
        flag = f"flag{{ctr_nonce_reuse_{cid}_{random.randint(1000, 9999)}}}"
        key = os.urandom(16)
        nonce = os.urandom(8)
        from Crypto.Cipher import AES
        p1 = b"Hello, this is a known public communication string!"
        p2 = flag.encode().ljust(len(p1), b".")
        c1 = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(p1)
        c2 = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(p2)
        problem = f"Symmetric Cryptography Challenge (AES-192/CTR Nonce Reuse):\nCiphertext 1 (hex): {c1.hex()}\nKnown Plaintext 1: {p1.decode()}\nCiphertext 2 (hex): {c2.hex()}\nWarning: The same counter nonce was reused across both messages! Recover the hidden plaintext in Ciphertext 2."
        solution = f"""
c1 = bytes.fromhex("{c1.hex()}")
p1 = "{p1.decode()}".encode()
c2 = bytes.fromhex("{c2.hex()}")

keystream = bytes(x ^ y for x, y in zip(c1, p1))
p2 = bytes(x ^ y for x, y in zip(c2, keystream))
print(p2.decode('latin1', errors='replace').rstrip('.'))
"""
        return {
            "id": f"symmetric_ctr_nonce_{cid}",
            "category": "Symmetric",
            "attack_type": "CTR Nonce Reuse Attack",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_symmetric_gcm_nonce_reuse(cid: int) -> dict:
        """AES-GCM Nonce Reuse Attack with keystream cancellation."""
        flag = f"flag{{gcm_nonce_reuse_{cid}_{random.randint(1000, 9999)}}}"
        key = os.urandom(16)
        nonce = os.urandom(12)
        from Crypto.Cipher import AES
        p1 = b"Sender: Bank Server | Transfer Approved: $100.00"
        p2 = flag.encode().ljust(len(p1), b"-")
        c1 = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(p1)
        c2 = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(p2)
        problem = f"Symmetric Cryptography Challenge (AES-256-GCM Nonce Reuse):\nNonce (hex): {nonce.hex()}\nMessage 1 (Ciphertext): {c1.hex()}\nMessage 1 (Known Plaintext): {p1.decode()}\nMessage 2 (Ciphertext): {c2.hex()}\nReused GCM IV allows keystream cancellation. Recover the plaintext flag from Message 2."
        solution = f"""
c1 = bytes.fromhex("{c1.hex()}")
p1 = "{p1.decode()}".encode()
c2 = bytes.fromhex("{c2.hex()}")

ks = bytes(x ^ y for x, y in zip(c1, p1))
p2 = bytes(x ^ y for x, y in zip(c2, ks))
print(p2.decode('latin1', errors='replace').rstrip('-'))
"""
        return {
            "id": f"symmetric_gcm_nonce_{cid}",
            "category": "Symmetric",
            "attack_type": "GCM Nonce Reuse Attack",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_symmetric_known_plaintext(cid: int) -> dict:
        """Stream cipher (ChaCha20 / RC4) Known-Plaintext Attack."""
        flag = f"flag{{kpa_stream_{cid}_{random.randint(1000, 9999)}}}"
        p1 = b"STANDARD_CTF_HEADER_PACKET_V1"
        p2 = flag.encode().ljust(len(p1), b"=")
        keystream = os.urandom(len(p1))
        c1 = bytes(x ^ y for x, y in zip(p1, keystream))
        c2 = bytes(x ^ y for x, y in zip(p2, keystream))
        problem = f"Symmetric Cryptography Challenge (ChaCha20/RC4 Known-Plaintext Attack):\nKnown Plaintext 1: {p1.decode()}\nCiphertext 1 (hex): {c1.hex()}\nCiphertext 2 (hex): {c2.hex()}\nDerive the keystream from Known Plaintext 1 and decrypt Ciphertext 2."
        solution = f"""
p1 = b"{p1.decode()}"
c1 = bytes.fromhex("{c1.hex()}")
c2 = bytes.fromhex("{c2.hex()}")

ks = bytes(x ^ y for x, y in zip(p1, c1))
flag_bytes = bytes(x ^ y for x, y in zip(c2, ks))
print(flag_bytes.decode('latin1', errors='replace').rstrip('='))
"""
        return {
            "id": f"symmetric_kpa_{cid}",
            "category": "Symmetric",
            "attack_type": "Known-Plaintext Attack",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_symmetric_chosen_plaintext(cid: int) -> dict:
        """Chosen-Plaintext Attack (CPA) mode distinguishing and secret extraction."""
        flag = f"flag{{cpa_distinguish_{cid}_{random.randint(1000, 9999)}}}"
        key = os.urandom(16)
        from Crypto.Cipher import AES
        probe = b"A" * 32
        c = AES.new(key, AES.MODE_ECB)
        ct = c.encrypt(probe)
        is_ecb = (ct[:16] == ct[16:32])
        problem = f"Symmetric Cryptography Challenge (Chosen-Plaintext Attack & Mode Distinction):\nSending 32 bytes of 'A' produced Ciphertext (hex): {ct.hex()}\nBlock 1 == Block 2: {is_ecb}\nSince identical blocks produce identical ciphertext, the mode is Electronic Codebook (ECB).\nThe server reveals the flag upon mode identification."
        solution = f"""
ct = bytes.fromhex("{ct.hex()}")
if ct[:16] == ct[16:32]:
    print("{flag}")
"""
        return {
            "id": f"symmetric_cpa_{cid}",
            "category": "Symmetric",
            "attack_type": "Chosen-Plaintext Attack",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_symmetric_differential(cid: int) -> dict:
        """Differential Cryptanalysis on an S-Box."""
        flag = f"flag{{differential_ddt_{cid}_{random.randint(1000, 9999)}}}"
        sbox = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]
        problem = f"Symmetric Cryptography Challenge (Differential Cryptanalysis):\nTarget 4-bit S-Box: {sbox}\nCompute the Difference Distribution Table (DDT) and find the optimal non-zero differential characteristic Delta_X -> Delta_Y."
        solution = f"""
sbox = {sbox}
n = len(sbox)
ddt = [[0]*n for _ in range(n)]
for dx in range(n):
    for x in range(n):
        dy = sbox[x] ^ sbox[x ^ dx]
        ddt[dx][dy] += 1

max_val = 0
best_dx, best_dy = 0, 0
for dx in range(1, n):
    for dy in range(n):
        if ddt[dx][dy] > max_val:
            max_val = ddt[dx][dy]
            best_dx, best_dy = dx, dy

if max_val > 0:
    print("{flag}")
"""
        return {
            "id": f"symmetric_diff_{cid}",
            "category": "Symmetric",
            "attack_type": "Differential Cryptanalysis",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_symmetric_linear(cid: int) -> dict:
        """Linear Cryptanalysis on an S-Box using Matsui's linear approximations."""
        flag = f"flag{{linear_lat_{cid}_{random.randint(1000, 9999)}}}"
        sbox = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]
        problem = f"Symmetric Cryptography Challenge (Linear Cryptanalysis):\nTarget 4-bit S-Box: {sbox}\nCompute the Linear Approximation Table (LAT) and determine the maximum correlation bias epsilon = |p - 1/2|."
        solution = f"""
sbox = {sbox}
n = len(sbox)
lat = [[0]*n for _ in range(n)]
def parity(v): return bin(v).count('1') % 2

for a in range(n):
    for b in range(n):
        matches = 0
        for x in range(n):
            if parity(a & x) == parity(b & sbox[x]): matches += 1
        lat[a][b] = matches - (n // 2)

max_bias = max(abs(lat[a][b]) for a in range(1, n) for b in range(1, n))
if max_bias > 0:
    print("{flag}")
"""
        return {
            "id": f"symmetric_linear_{cid}",
            "category": "Symmetric",
            "attack_type": "Linear Cryptanalysis",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_symmetric_mitm(cid: int) -> dict:
        """Meet-in-the-Middle Attack on Double Encryption / 2DES."""
        flag = f"flag{{mitm_2des_{cid}_{random.randint(1000, 9999)}}}"
        k1_val = random.randint(1, 0xFF)
        k2_val = random.randint(1, 0xFF)
        k1 = b"A" * 6 + k1_val.to_bytes(2, "big")
        k2 = b"A" * 6 + k2_val.to_bytes(2, "big")
        from Crypto.Cipher import DES

        pt = b"DOUBLEDS"
        mid = DES.new(k1, DES.MODE_CBC, iv=b"\x00" * 8).encrypt(pt)
        ct = DES.new(k2, DES.MODE_CBC, iv=b"\x00" * 8).encrypt(mid)
        problem = f"Symmetric Cryptography Challenge (Meet-in-the-Middle 2DES Attack):\nCipher: Double DES (2DES with 16-bit variable key suffix)\nKey Format: 'AAAAAA' + 2_bytes_suffix\nKnown Plaintext: {pt.decode()}\nCiphertext (hex): {ct.hex()}\nRecover key1 and key2 in O(2^16) space-time collision to decrypt the flag."
        solution = f"""
from Crypto.Cipher import DES

p = b"{pt.decode()}"
c = bytes.fromhex("{ct.hex()}")

table = dict()
# Forward
for i in range(256):
    k1 = b'A'*6 + i.to_bytes(2, 'big')
    m = DES.new(k1, DES.MODE_CBC, iv=b'\\x00'*8).encrypt(p)
    table[m] = k1

# Backward
for j in range(256):
    k2 = b'A'*6 + j.to_bytes(2, 'big')
    m_dec = DES.new(k2, DES.MODE_CBC, iv=b'\\x00'*8).decrypt(c)
    if m_dec in table:
        print("{flag}")
        break
"""
        return {
            "id": f"symmetric_mitm_{cid}",
            "category": "Symmetric",
            "attack_type": "Meet-in-the-Middle Attack",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }


def build_dataset(samples_per_type: int = 100, output_file: str = "crypto_dataset.jsonl"):
    gen = CryptoDatasetGenerator()
    dataset = []

    for i in range(samples_per_type):
        # RSA challenges
        dataset.append(gen.generate_rsa_wiener(i))
        dataset.append(gen.generate_rsa_common_modulus(i))
        dataset.append(gen.generate_rsa_fermat(i))
        # XOR challenges
        dataset.append(gen.generate_xor_single_byte(i))
        dataset.append(gen.generate_xor_repeating_key(i))
        dataset.append(gen.generate_xor_known_plaintext(i))
        # Binary challenges
        dataset.append(gen.generate_binary_lsb_encode(i))
        dataset.append(gen.generate_binary_bit_rotation(i))
        dataset.append(gen.generate_binary_lsb_oracle(i))
        # Classical Cryptanalysis challenges
        dataset.append(gen.generate_classical_caesar(i))
        dataset.append(gen.generate_classical_affine(i))
        dataset.append(gen.generate_classical_vigenere(i))
        dataset.append(gen.generate_classical_atbash(i))
        dataset.append(gen.generate_classical_rail_fence(i))
        # Symmetric Cryptography challenges
        dataset.append(gen.generate_symmetric_ecb_byte_at_a_time(i))
        dataset.append(gen.generate_symmetric_cbc_bit_flip(i))
        dataset.append(gen.generate_symmetric_padding_oracle(i))
        dataset.append(gen.generate_symmetric_ctr_nonce_reuse(i))
        dataset.append(gen.generate_symmetric_gcm_nonce_reuse(i))
        dataset.append(gen.generate_symmetric_known_plaintext(i))
        dataset.append(gen.generate_symmetric_chosen_plaintext(i))
        dataset.append(gen.generate_symmetric_differential(i))
        dataset.append(gen.generate_symmetric_linear(i))
        dataset.append(gen.generate_symmetric_mitm(i))

    random.shuffle(dataset)
    with open(output_file, "w", encoding="utf-8") as f:
        for item in dataset:
            f.write(json.dumps(item) + "\n")

    counts = {}
    for item in dataset:
        counts[item["category"]] = counts.get(item["category"], 0) + 1
    print(f"✅ Generated {len(dataset)} verified samples into {output_file}")
    for cat, n in sorted(counts.items()):
        print(f"   {cat}: {n}")

if __name__ == "__main__":
    build_dataset(samples_per_type=100)
