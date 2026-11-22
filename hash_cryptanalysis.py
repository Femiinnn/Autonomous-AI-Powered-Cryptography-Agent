# -*- coding: utf-8 -*-
"""
hash_cryptanalysis.py — Autonomous Hash Cryptanalysis Suite
══════════════════════════════════════════════════════════
Provides comprehensive hash identification, dictionary/brute-force recovery,
Merkle-Damgård length extension analysis, birthday collision demonstrations,
and command synthesis for offline recovery tools.
"""

import hashlib
import struct
import math
import itertools
from typing import Dict, List, Optional, Tuple, Any

# Common CTF salt/password candidate words
COMMON_WORDLIST = [
    "admin", "password", "123456", "root", "toor", "guest", "test",
    "letmein", "welcome", "shadow", "master", "crypto", "secret",
    "flag", "ctf", "pico", "hack", "cyber", "pass123", "default"
]

HASH_SPECS = {
    "md5":      {"len_hex": 32,  "bits": 128, "md_construction": True,  "block_size": 64},
    "sha1":     {"len_hex": 40,  "bits": 160, "md_construction": True,  "block_size": 64},
    "sha224":   {"len_hex": 56,  "bits": 224, "md_construction": True,  "block_size": 64},
    "sha256":   {"len_hex": 64,  "bits": 256, "md_construction": True,  "block_size": 64},
    "sha384":   {"len_hex": 96,  "bits": 384, "md_construction": True,  "block_size": 128},
    "sha512":   {"len_hex": 128, "bits": 512, "md_construction": True,  "block_size": 128},
    "sha3_256": {"len_hex": 64,  "bits": 256, "md_construction": False, "block_size": 136},
    "ntlm":     {"len_hex": 32,  "bits": 128, "md_construction": False, "block_size": 64},
}


def identify_hash_type(hash_str: str) -> List[Dict[str, Any]]:
    """Identifies possible hash algorithms from hex string length and character set."""
    h = hash_str.strip().lower()
    matches = []
    if not all(c in "0123456789abcdef" for c in h):
        return matches

    for algo, spec in HASH_SPECS.items():
        if len(h) == spec["len_hex"]:
            matches.append({
                "algorithm": algo,
                "type": algo,
                "algo": algo,
                "bits": spec["bits"],
                "merkle_damgard": spec["md_construction"],
                "block_size": spec["block_size"]
            })
    return matches


class CrackResult(dict):
    """Result dictionary that also stringifies to plaintext for flexible API access."""
    def __str__(self):
        return self.get("plaintext", "")
    def __bool__(self):
        return self.get("status") == "cracked"


def compute_hash(arg1: Any, arg2: Any) -> str:
    """Computes digest for supported algorithms. Accepts (algo, data) or (data, algo)."""
    if isinstance(arg1, (bytes, bytearray)):
        data, algo = bytes(arg1), str(arg2).lower()
    elif isinstance(arg2, (bytes, bytearray)):
        algo, data = str(arg1).lower(), bytes(arg2)
    elif isinstance(arg1, str) and isinstance(arg2, str):
        if arg1.lower() in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "ntlm"):
            algo, data = arg1.lower(), arg2.encode("utf-8")
        else:
            data, algo = arg1.encode("utf-8"), arg2.lower()
    else:
        algo, data = str(arg1).lower(), bytes(arg2)

    if algo == "ntlm":
        try:
            return hashlib.new('md4', data.decode('latin1', errors='ignore').encode('utf-16le')).hexdigest()
        except Exception:
            return ""
    if hasattr(hashlib, algo):
        h = getattr(hashlib, algo)()
        h.update(data)
        return h.hexdigest()
    return ""


def dictionary_attack(target_hash: str, algo: str, wordlist: Optional[List[str]] = None) -> CrackResult:
    """Attempts fast wordlist and targeted variation lookup."""
    target_hash = target_hash.strip().lower()
    words = (wordlist or []) + COMMON_WORDLIST
    variations = []

    for w in words:
        variations.append(w)
        variations.append(w.upper())
        variations.append(w.capitalize())
        variations.append(w + "123")
        variations.append(w + "!")
        variations.append(w + "2024")

    for cand in variations:
        digest = compute_hash(algo, cand.encode())
        if digest.lower() == target_hash:
            return CrackResult({
                "status": "cracked",
                "plaintext": cand,
                "hash": target_hash,
                "algo": algo
            })
    return CrackResult({
        "status": "failed",
        "plaintext": None,
        "hash": target_hash,
        "algo": algo
    })


def brute_force_attack(target_hash: str, algo: str, charset: str = "0123456789abcdefghijklmnopqrstuvwxyz", max_len: int = 4) -> CrackResult:
    """Exhaustive brute force for short secret strings or numeric PINs."""
    target_hash = target_hash.strip().lower()
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            cand = "".join(combo)
            if compute_hash(algo, cand.encode()).lower() == target_hash:
                return CrackResult({
                    "status": "cracked",
                    "plaintext": cand,
                    "hash": target_hash,
                    "algo": algo
                })
    return CrackResult({
        "status": "failed",
        "plaintext": None,
        "hash": target_hash,
        "algo": algo
    })


def generate_merkle_damgard_padding(msg_len_bytes: int, endian_or_algo: str = ">Q") -> bytes:
    """Generates standard MD padding for 64-byte block algorithms (MD5, SHA1, SHA256)."""
    endian = "<Q" if endian_or_algo.lower() == "md5" else (endian_or_algo if endian_or_algo.startswith(("<", ">")) else ">Q")
    pad = b"\x80"
    mod = (msg_len_bytes + len(pad)) % 64
    if mod <= 56:
        pad += b"\x00" * (56 - mod)
    else:
        pad += b"\x00" * (64 + 56 - mod)
    total_bits = msg_len_bytes * 8
    pad += struct.pack(endian, total_bits)
    return pad


def length_extension_analysis(original_hash: str, added_data: bytes, key_len: int, algo: str = "sha256") -> Dict[str, Any]:
    """
    Computes length extension structure and forged message payload for MAC(key || data).
    """
    pad = generate_merkle_damgard_padding(key_len)
    forged_suffix = pad + added_data
    return {
        "status": "ready",
        "algorithm": algo,
        "key_length_tested": key_len,
        "padding_hex": pad.hex(),
        "forged_extension_suffix_hex": forged_suffix.hex(),
        "note": "Use reconstructed internal state words as initial IV for appending data."
    }


def generate_cracking_commands(target_hash: str, algo: str = "sha256", wordlist_path: str = "rockyou.txt") -> Dict[str, str]:
    """Synthesizes execution commands for offline cracking engines."""
    hashcat_modes = {
        "md5": "0", "sha1": "100", "sha256": "1400", "sha512": "1700", "ntlm": "1000"
    }
    mode = hashcat_modes.get(algo.lower(), "0")
    return {
        "hashcat": f"hashcat -m {mode} -a 0 '{target_hash}' {wordlist_path} --status --status-timer=10",
        "john": f"echo '{target_hash}' > hash.txt && john --format=raw-{algo.lower()} --wordlist={wordlist_path} hash.txt"
    }


def birthday_collision_demo(hash_bit_size: int = 16, bits: Optional[int] = None) -> Dict[str, Any]:
    """Demonstrates birthday collision attack finding m1 != m2 with matching truncated hash."""
    if bits is not None:
        hash_bit_size = bits
    seen = {}
    mask = (1 << hash_bit_size) - 1
    counter = 0

    while True:
        m = f"msg_{counter}".encode()
        h_val = int(hashlib.sha256(m).hexdigest()[:8], 16) & mask
        if h_val in seen:
            prev_m = seen[h_val]
            return {
                "collision_found": True,
                "truncated_bits": hash_bit_size,
                "msg1": prev_m.decode(),
                "msg2": m.decode(),
                "truncated_hash_hex": hex(h_val),
                "iterations": counter,
                "expected_iterations": int(math.sqrt(math.pi * (2 ** hash_bit_size) / 2))
            }
        seen[h_val] = m
        counter += 1
