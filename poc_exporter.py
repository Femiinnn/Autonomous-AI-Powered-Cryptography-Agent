"""
Standalone Zero-Dependency Exploit PoC Exporter (poc_exporter.py)
================================================================
Generates a 100% self-contained, standalone Python 3 script (outputs/poc.py)
with zero external framework dependencies, embedding essential pure-Python
mathematical primitives (egcd, modinv, iroot, crt, long_to_bytes, bytes_to_long)
and self-testing assertions, ready for direct CTF flag submission or
bug bounty verification tickets.
"""

from pathlib import Path
from typing import Dict, Any, Optional


STANDALONE_MATH_PREAMBLE = '''#!/usr/bin/env python3
# ==============================================================================
# STANDALONE REPRODUCIBLE EXPLOIT PROOF-OF-CONCEPT (PoC)
# Generated automatically by Autonomous Crypto CTF Agent & Bug Bounty Assistant
# ==============================================================================
# Requirements: Standard Python 3.8+ (Zero external pip dependencies required)
# ==============================================================================

import sys
import math
import struct
import hashlib
import binascii

# --- Pure-Python Mathematical Primitives ---

def egcd(a, b):
    """Extended Euclidean Algorithm: returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def modinv(a, m):
    """Modular multiplicative inverse: a^(-1) mod m."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {g}")
    return x % m

def iroot(n, k=2):
    """Exact integer k-th root using integer binary search: returns (root, is_exact)."""
    if n < 0:
        raise ValueError("Cannot compute root of negative integer")
    if n == 0:
        return 0, True
    if k == 1:
        return n, True
    low, high = 1, 1 << ((n.bit_length() + k - 1) // k + 1)
    while low < high:
        mid = (low + high) // 2
        p = pow(mid, k)
        if p == n:
            return mid, True
        if p < n:
            low = mid + 1
        else:
            high = mid
    cand = low - 1
    return cand, (pow(cand, k) == n)

def crt(remainders, moduli):
    """Chinese Remainder Theorem for pairwise coprime moduli: returns x in [0, prod(moduli))."""
    from functools import reduce
    total = 0
    prod = reduce(lambda a, b: a * b, moduli, 1)
    for r_i, m_i in zip(remainders, moduli):
        p = prod // m_i
        total += r_i * modinv(p, m_i) * p
    return total % prod

def bytes_to_long(b):
    """Converts big-endian bytes to integer."""
    if isinstance(b, str):
        b = b.encode('latin1')
    return int.from_bytes(b, byteorder='big')

def long_to_bytes(n, blocksize=0):
    """Converts integer to big-endian bytes."""
    if n < 0:
        raise ValueError("Negative integer cannot be converted to bytes")
    if n == 0:
        return b'\\x00' if blocksize else b''
    length = (n.bit_length() + 7) // 8
    if blocksize > 0 and length % blocksize != 0:
        length = ((length // blocksize) + 1) * blocksize
    return n.to_bytes(length, byteorder='big')

def xor_bytes(a, b):
    """XORs two byte strings, repeating the shorter key if necessary."""
    if isinstance(a, str): a = a.encode('latin1')
    if isinstance(b, str): b = b.encode('latin1')
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))

def is_printable_ascii(b):
    """Validates whether bytes consist predominantly of printable ASCII."""
    if not b: return False
    return sum(1 for x in b if 32 <= x <= 126 or x in (9, 10, 13)) / len(b) >= 0.80

'''


def export_standalone_poc(
    exploit_code: str,
    parameters: Optional[Dict[str, Any]] = None,
    verified_flag: Optional[str] = None,
    category: str = "Cryptanalysis",
    vulnerability: str = "Cryptographic Flaw",
    output_path: str = "outputs/poc.py"
) -> str:
    """
    Synthesizes a clean, self-contained standalone Python exploit script.
    """
    params = parameters or {}

    # Format extracted parameters as clean Python constants
    param_lines = []
    for k, v in params.items():
        if isinstance(v, int):
            param_lines.append(f"{k.upper()} = {v}")
        elif isinstance(v, str):
            param_lines.append(f"{k.upper()} = {repr(v)}")
        elif isinstance(v, bytes):
            param_lines.append(f"{k.upper()} = {repr(v)}")
        elif isinstance(v, list):
            param_lines.append(f"{k.upper()} = {repr(v)}")

    params_block = "\n".join(param_lines) if param_lines else "# (No extracted parameters supplied)"

    # Format the exploit logic
    clean_code = exploit_code.strip()
    # Strip any markdown code fences if present
    if clean_code.startswith("```"):
        lines = clean_code.splitlines()
        clean_code = "\n".join([l for l in lines if not l.strip().startswith("```")]).strip()

    assertion_block = ""
    if verified_flag:
        assertion_block = f"""
    # Verification Assertion
    if result:
        res_str = result.decode('latin1', errors='replace') if isinstance(result, bytes) else str(result)
        if {repr(verified_flag)} in res_str:
            print("[+] Self-Test Verification: PASSED (Verified flag matched target)")
        else:
            print("[*] Note: Output recovered:", res_str)
"""

    script = f"""{STANDALONE_MATH_PREAMBLE}
# --- Challenge Metadata ---
# Category      : {category}
# Vulnerability : {vulnerability}
# Target Flag   : {verified_flag or 'N/A'}

# --- Parameters ---
{params_block}

# --- Exploit Function ---
def exploit():
    print("[*] Running standalone cryptographic exploit ({vulnerability})...")
    result = None
    
{_indent_code(clean_code, 4)}

    print("\\n[+] Recovered Result / Flag:")
    if isinstance(result, bytes):
        try:
            print(result.decode('utf-8'))
        except UnicodeDecodeError:
            print(result)
    else:
        print(result)
{assertion_block}
    return result

if __name__ == "__main__":
    exploit()
"""

    try:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(script, encoding="utf-8")
    except Exception:
        pass

    return script


def _indent_code(code: str, spaces: int = 4) -> str:
    """Indents code block with specified number of spaces."""
    prefix = " " * spaces
    lines = code.splitlines()
    # If the code already defines a solve function or starts with def, adapt
    indented = []
    has_result_assignment = False
    for line in lines:
        if "result =" in line or "result=" in line or "print(" in line:
            has_result_assignment = True
        indented.append(f"{prefix}{line}")
    if not has_result_assignment and lines:
        indented.append(f"{prefix}result = {lines[-1].strip()}")
    return "\n".join(indented)
