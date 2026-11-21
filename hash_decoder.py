# -*- coding: utf-8 -*-
r"""
hash_decoder.py — Auto-detect and recursively decode encoding & hash types
for the Crypto CTF Agent.

Supported Encodings & Transformations:
  - Base64 (Standard, URL-safe, unpadded, padded)
  - Base32 (Standard RFC 4648, Base32hex)
  - Base16 (RFC 4648 Base16 uppercase/lowercase)
  - Hexadecimal (Continuous, space-separated, colon-separated, C/Python escapes \x.., 0x.. arrays)
  - Hexadecimal-to-bytes conversion
  - Binary (Continuous 8-bit/7-bit, spaced bytes, 0b.. prefixes)
  - ASCII / Unicode (Unicode escapes \\uXXXX, \\UXXXXXXXX, HTML/XML numeric character references)
  - URL encoding (Percent-encoding %XX, query string, %uXXXX Unicode)
  - Base85 (RFC 1924 / Git Base85 and Ascii85 / Adobe Base85 <~...~>)
  - Base58 (Bitcoin, Ripple, and Flickr alphabets)
  - Morse code (Letters, digits, punctuation with '.', '-', '_', '/', '|')
  - Decimal ASCII (Space/comma/semicolon/dash-separated ASCII byte values)
  - ROT transformations (ROT1 through ROT25 Caesar rotation, ROT47 printable ASCII, ROT5 digits)
  - UTF-8 (Multi-byte decoding & mojibake recovery)
  - Gzip / Zlib (Automatic decompression of gzip \\x1f\\x8b and zlib/deflate \\x78\\x9c streams)

Recursive Multi-Layer Decoding:
  CTF challenges frequently combine multiple encodings (e.g. Base64 → Gzip → Hex → Decimal ASCII).
  Repeatedly decodes and decompresses across text and raw byte boundaries up to 15 layers.
"""

import re
import base64
import binascii
import urllib.parse
import hashlib
import zlib
import gzip
import html
import codecs
from typing import Optional, List, Dict, Any, Tuple, Union

# ─── Hash Fingerprinting Patterns ─────────────────────────────────────────────
HASH_PATTERNS: List[tuple] = [
    ("CRC32",          r"^[a-fA-F0-9]{8}$",    "32-bit"),
    ("xxHash64",       r"^[a-fA-F0-9]{16}$",   "64-bit"),
    ("MD5",            r"^[a-fA-F0-9]{32}$",   "128-bit"),
    ("NTLM",           r"^[a-fA-F0-9]{32}$",   "128-bit"),
    ("MD4",            r"^[a-fA-F0-9]{32}$",   "128-bit"),
    ("LM Hash",        r"^[a-fA-F0-9]{32}$",   "128-bit"),
    ("SHA-1",          r"^[a-fA-F0-9]{40}$",   "160-bit"),
    ("RIPEMD-160",     r"^[a-fA-F0-9]{40}$",   "160-bit"),
    ("Tiger-192",      r"^[a-fA-F0-9]{48}$",   "192-bit"),
    ("SHA-224",        r"^[a-fA-F0-9]{56}$",   "224-bit"),
    ("SHA3-224",       r"^[a-fA-F0-9]{56}$",   "224-bit"),
    ("SHA-256",        r"^[a-fA-F0-9]{64}$",   "256-bit"),
    ("SHA3-256",       r"^[a-fA-F0-9]{64}$",   "256-bit"),
    ("HAVAL-256",      r"^[a-fA-F0-9]{64}$",   "256-bit"),
    ("GOST R 34.11",   r"^[a-fA-F0-9]{64}$",   "256-bit"),
    ("SHA-384",        r"^[a-fA-F0-9]{96}$",   "384-bit"),
    ("SHA3-384",       r"^[a-fA-F0-9]{96}$",   "384-bit"),
    ("SHA-512",        r"^[a-fA-F0-9]{128}$",  "512-bit"),
    ("SHA3-512",       r"^[a-fA-F0-9]{128}$",  "512-bit"),
    ("Whirlpool",      r"^[a-fA-F0-9]{128}$",  "512-bit"),
    ("bcrypt",         r"^\$2[aby]?\$\d{2}\$.{53}$", "bcrypt"),
    ("Argon2",         r"^\$argon2",            "argon2"),
    ("scrypt",         r"^\$s0\$",              "scrypt"),
]

# ─── Morse Code Table ─────────────────────────────────────────────────────────
MORSE_TO_CHAR: Dict[str, str] = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
    '.-.-.-': '.', '--..--': ',', '..--..': '?',
    '-..-.': '/', '---...': ':', '-....-': '-', '.--.-.': '@',
}

COMMON_ENGLISH_WORDS = {
    'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had',
    'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his',
    'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy',
    'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use', 'flag', 'ctf',
    'hello', 'world', 'secret', 'password', 'encode', 'decode', 'crypto',
    'key', 'test', 'admin', 'user', 'access', 'token', 'system', 'hidden'
}


def _safe_decode_bytes(b: bytes) -> Optional[str]:
    """Attempt UTF-8/ASCII decode, return None if result contains non-printable binary chars."""
    if not b:
        return None
    try:
        s = b.decode('utf-8')
        if all(c.isprintable() or c in '\n\r\t' for c in s):
            return s
        return None
    except UnicodeDecodeError:
        try:
            # Fallback to ascii
            s = b.decode('ascii')
            if all(c.isprintable() or c in '\n\r\t' for c in s):
                return s
        except UnicodeDecodeError:
            pass
        return None


def _is_more_english(decoded: str, original: str) -> bool:
    """Return True if decoded contains common English words, CTF flag syntax, or higher word hits."""
    dec_lower = decoded.lower()
    if any(k in dec_lower for k in ('flag{', 'ctf{', 'key{', 'secret{', 'flag:', 'congratulations')):
        return True
    words_decoded = set(re.findall(r'[a-z]{2,}', dec_lower))
    words_original = set(re.findall(r'[a-z]{2,}', original.lower()))
    hits_decoded = len(words_decoded & COMMON_ENGLISH_WORDS)
    hits_original = len(words_original & COMMON_ENGLISH_WORDS)
    return hits_decoded > hits_original and hits_decoded >= 1


# ─── Individual Encoders & Decoders ──────────────────────────────────────────

def _try_gzip_zlib_decompression(data: bytes) -> Optional[str]:
    """Inspects raw byte payloads for Gzip or Zlib/Deflate streams and decompresses them."""
    if len(data) < 4:
        return None
    # Gzip stream magic: \x1f\x8b
    if data.startswith(b'\x1f\x8b'):
        try:
            decomp = gzip.decompress(data)
            dec_str = _safe_decode_bytes(decomp)
            if dec_str:
                return dec_str
            # If decompressed bytes are binary hex representation
            return decomp.hex()
        except Exception:
            pass

    # Zlib header magic: \x78\x9c, \x78\x01, \x78\xda, \x78\x5e
    if data.startswith((b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e', b'\x78\x20', b'\x78\xbb')):
        try:
            decomp = zlib.decompress(data)
            dec_str = _safe_decode_bytes(decomp)
            if dec_str:
                return dec_str
            return decomp.hex()
        except Exception:
            pass

    # Raw Deflate (wbits=-15)
    try:
        decomp = zlib.decompress(data, -15)
        dec_str = _safe_decode_bytes(decomp)
        if dec_str:
            return dec_str
    except Exception:
        pass

    return None


def _try_base64(s: str) -> Optional[str]:
    s_clean = s.strip()
    padded = s_clean + '=' * (-len(s_clean) % 4)
    for variant in [padded, s_clean]:
        try:
            raw = base64.b64decode(variant, validate=True)
            # Check if payload is gzip/zlib compressed
            gz_res = _try_gzip_zlib_decompression(raw)
            if gz_res:
                return gz_res
            res = _safe_decode_bytes(raw)
            if res:
                return res
        except Exception:
            pass
    # URL-safe Base64
    try:
        raw = base64.urlsafe_b64decode(padded)
        gz_res = _try_gzip_zlib_decompression(raw)
        if gz_res:
            return gz_res
        res = _safe_decode_bytes(raw)
        if res:
            return res
    except Exception:
        pass
    return None


def _try_base32(s: str) -> Optional[str]:
    s_clean = s.strip().upper()
    padded = s_clean + '=' * (-len(s_clean) % 8)
    try:
        raw = base64.b32decode(padded)
        gz_res = _try_gzip_zlib_decompression(raw)
        if gz_res:
            return gz_res
        return _safe_decode_bytes(raw)
    except Exception:
        pass
    # Base32hex variant (RFC 4648 extended hex alphabet 0-9A-V)
    try:
        raw = base64.b32hexdecode(padded)
        return _safe_decode_bytes(raw)
    except Exception:
        pass
    return None


def _try_base16(s: str) -> Optional[str]:
    """RFC 4648 Base16 decoding (pure hex without 0x/escapes)."""
    s_clean = s.strip()
    if not re.match(r'^[0-9A-Fa-f]+$', s_clean) or len(s_clean) % 2 != 0 or len(s_clean) < 4:
        return None
    try:
        raw = base64.b16decode(s_clean.upper())
        gz_res = _try_gzip_zlib_decompression(raw)
        if gz_res:
            return gz_res
        return _safe_decode_bytes(raw)
    except Exception:
        return None


def _try_hex(s: str) -> Optional[str]:
    """
    Decodes Hexadecimal in varied formats:
    - Continuous: '666c6167'
    - Spaced: '66 6c 61 67'
    - Colon-delimited: '66:6c:61:67'
    - C/Python byte escapes: '\\x66\\x6c\\x61\\x67'
    - Comma/Array: '0x66, 0x6c' or '[0x66, 0x6c]'
    """
    cleaned = s.strip()
    # Normalize common representations
    cleaned = re.sub(r'[\[\]\(\)\{\}]', '', cleaned)
    cleaned = cleaned.replace('\\x', '').replace('0x', '').replace('0X', '')
    cleaned = re.sub(r'[\s,;:\-_]+', '', cleaned)

    if not re.match(r'^[0-9a-fA-F]+$', cleaned) or len(cleaned) % 2 != 0 or len(cleaned) < 2:
        return None
    try:
        raw = binascii.unhexlify(cleaned)
        # Check for gzip/zlib compressed payload
        gz_res = _try_gzip_zlib_decompression(raw)
        if gz_res:
            return gz_res
        return _safe_decode_bytes(raw)
    except Exception:
        return None


def _try_binary(s: str) -> Optional[str]:
    """
    Decodes Binary in 8-bit or 7-bit representations:
    - Spaced: '01100110 01101100 01100001 01100111'
    - Continuous: '01100110011011000110000101100111'
    - Prefixed: '0b01100110, 0b01101100'
    """
    cleaned = s.strip().replace('0b', '').replace('0B', '')
    tokens = [t.strip() for t in re.split(r'[\s,;]+', cleaned) if t.strip()]

    # If space-separated tokens of 7 or 8 bits
    if len(tokens) >= 2 and all(re.match(r'^[01]{7,8}$', t) for t in tokens):
        try:
            raw = bytes(int(t, 2) for t in tokens)
            gz_res = _try_gzip_zlib_decompression(raw)
            if gz_res:
                return gz_res
            return _safe_decode_bytes(raw)
        except Exception:
            pass

    # Continuous binary string
    continuous = re.sub(r'\s+', '', cleaned)
    if re.match(r'^[01]+$', continuous) and len(continuous) >= 8 and len(continuous) % 8 == 0:
        try:
            raw = bytes(int(continuous[i:i+8], 2) for i in range(0, len(continuous), 8))
            gz_res = _try_gzip_zlib_decompression(raw)
            if gz_res:
                return gz_res
            return _safe_decode_bytes(raw)
        except Exception:
            pass

    return None


def _try_decimal_ascii(s: str) -> Optional[str]:
    """
    Decodes Decimal ASCII codes:
    e.g. '102 108 97 103 123 116 101 115 116 125' -> 'flag{test}'
    Separated by spaces, commas, semicolons, or dashes.
    """
    tokens = [t.strip() for t in re.split(r'[\s,;\-]+', s.strip()) if t.strip()]
    if len(tokens) < 3:
        return None

    if not all(t.isdigit() for t in tokens):
        return None

    nums = [int(t) for t in tokens]
    # Verify standard ASCII or valid byte values
    if not all(0 <= n <= 255 for n in nums):
        # Might be Unicode codepoint numbers
        if all(0 <= n <= 0x10FFFF for n in nums):
            try:
                res = ''.join(chr(n) for n in nums)
                if any(c.isprintable() for c in res) and len(res) >= 3:
                    return res
            except Exception:
                return None
        return None

    # Count printable ASCII characters
    printable_count = sum(32 <= n <= 126 or n in (9, 10, 13) for n in nums)
    if (printable_count / len(nums)) < 0.75:
        return None

    try:
        raw = bytes(nums)
        gz_res = _try_gzip_zlib_decompression(raw)
        if gz_res:
            return gz_res
        return _safe_decode_bytes(raw)
    except Exception:
        return None


def _try_unicode_ascii_escapes(s: str) -> Optional[str]:
    """
    Decodes Unicode and ASCII escape formats:
    - \\uXXXX or \\UXXXXXXXX
    - HTML/XML numeric character references: &#102; or &#x66;
    - Standard slash escapes: \\x66, \\n, \\t
    """
    # 1. HTML numeric entities
    if '&#' in s:
        try:
            unescaped = html.unescape(s)
            if unescaped != s and any(c.isprintable() for c in unescaped):
                return unescaped
        except Exception:
            pass

    # 2. \\uXXXX or \\UXXXXXXXX Unicode escapes
    if '\\u' in s or '\\U' in s or '\\x' in s:
        try:
            decoded = codecs.decode(s, 'unicode_escape')
            if decoded != s and any(c.isprintable() for c in decoded):
                return decoded
        except Exception:
            pass

    return None


def _try_url(s: str) -> Optional[str]:
    """Decodes standard percent-encoded URLs and %uXXXX Unicode URL encodings."""
    if '%' not in s:
        return None
    # Handle %uXXXX IIS unicode percent encoding
    s_norm = re.sub(r'%u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)
    try:
        decoded = urllib.parse.unquote_plus(s_norm)
        if decoded != s:
            return decoded
    except Exception:
        pass
    return None


def _try_base85(s: str) -> Optional[str]:
    """Decodes both RFC 1924 / Git Base85 and Ascii85 (standard & Adobe) variants."""
    s_clean = s.strip()
    if len(s_clean) < 5:
        return None

    # 1. Ascii85 (Standard / ZeroMQ)
    try:
        raw = base64.a85decode(s_clean, adobe=False)
        gz_res = _try_gzip_zlib_decompression(raw)
        if gz_res:
            return gz_res
        res = _safe_decode_bytes(raw)
        if res and any(c.isalnum() for c in res):
            return res
    except Exception:
        pass

    # 2. Ascii85 (Adobe variant enclosed in <~...~>)
    try:
        raw = base64.a85decode(s_clean, adobe=True)
        gz_res = _try_gzip_zlib_decompression(raw)
        if gz_res:
            return gz_res
        res = _safe_decode_bytes(raw)
        if res and any(c.isalnum() for c in res):
            return res
    except Exception:
        pass

    # 3. RFC 1924 / Git Base85 variant
    try:
        raw = base64.b85decode(s_clean)
        gz_res = _try_gzip_zlib_decompression(raw)
        if gz_res:
            return gz_res
        res = _safe_decode_bytes(raw)
        if res and any(c.isalnum() for c in res):
            return res
    except Exception:
        pass

    return None


def _try_base58(s: str) -> Optional[str]:
    """Decodes Base58 using Bitcoin, Ripple, or Flickr alphabets."""
    s_clean = s.strip()
    if len(s_clean) < 4:
        return None

    ALPHABETS = [
        ("Bitcoin", '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'),
        ("Ripple",  'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxz'),
        ("Flickr",  '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ')
    ]

    for name, alphabet in ALPHABETS:
        if all(c in alphabet for c in s_clean):
            try:
                n = 0
                for char in s_clean:
                    n = n * 58 + alphabet.index(char)
                result_bytes = []
                while n > 0:
                    result_bytes.append(n % 256)
                    n //= 256
                leading_zeros = len(s_clean) - len(s_clean.lstrip(alphabet[0]))
                result_bytes.extend([0] * leading_zeros)
                raw = bytes(reversed(result_bytes))
                gz_res = _try_gzip_zlib_decompression(raw)
                if gz_res:
                    return gz_res
                dec = _safe_decode_bytes(raw)
                if dec and any(c.isalpha() for c in dec):
                    return dec
            except Exception:
                pass

    return None


def _try_morse(s: str) -> Optional[str]:
    """Decodes Morse code supporting '.', '-', '_', '/', and '|' separators."""
    s_clean = s.strip()
    if not re.match(r'^[.\-_/| ]+$', s_clean) or len(s_clean) < 3:
        return None

    # Normalize dash and word delimiters
    s_norm = s_clean.replace('_', '-').replace('|', ' / ')
    words = [w.strip() for w in re.split(r'\s*/\s*|\s{2,}', s_norm) if w.strip()]
    if not words:
        return None

    try:
        decoded_words = []
        for word in words:
            letters = [MORSE_TO_CHAR[c] for c in word.split() if c in MORSE_TO_CHAR]
            if letters:
                decoded_words.append(''.join(letters))
        if decoded_words:
            result = ' '.join(decoded_words)
            if len(result) >= 2 and any(c.isalnum() for c in result):
                return result
    except Exception:
        pass
    return None


def _try_rot_transformations(s: str) -> Optional[Tuple[str, str]]:
    """
    Evaluates ROT transformations:
    - All 25 ROT shifts (Caesar rotation)
    - ROT47 (printable ASCII 33..126)
    - ROT5 (digits)

    Returns: (decoded_text, algorithm_name) or None
    """
    if not s or len(s) < 3:
        return None

    # 1. Flag search or strong English word matches across all 25 Caesar shifts
    best_candidate = None
    best_shift = 0
    best_score = 0

    for shift in range(1, 26):
        cand_chars = []
        for c in s:
            if 'a' <= c <= 'z':
                cand_chars.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                cand_chars.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            else:
                cand_chars.append(c)
        cand = ''.join(cand_chars)
        cand_lower = cand.lower()

        # Immediate hit on CTF flag pattern
        if any(k in cand_lower for k in ('flag{', 'ctf{', 'key{', 'secret{')):
            return (cand, f"ROT{shift}")

        words = set(re.findall(r'[a-z]{3,}', cand_lower))
        hits = len(words & COMMON_ENGLISH_WORDS)
        if hits > best_score:
            best_score = hits
            best_candidate = cand
            best_shift = shift

    if best_candidate and best_score >= 2 and _is_more_english(best_candidate, s):
        return (best_candidate, f"ROT{best_shift}")

    # 2. ROT47 (ASCII characters 33 '!' through 126 '~')
    rot47_chars = []
    has_rot47_chars = False
    for c in s:
        code = ord(c)
        if 33 <= code <= 126:
            has_rot47_chars = True
            rot47_chars.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            rot47_chars.append(c)
    rot47_cand = ''.join(rot47_chars)
    if has_rot47_chars and rot47_cand != s:
        rot47_lower = rot47_cand.lower()
        if any(k in rot47_lower for k in ('flag{', 'ctf{', 'key{')) or _is_more_english(rot47_cand, s):
            return (rot47_cand, "ROT47")

    return None


def _try_utf8_mojibake(s: str) -> Optional[str]:
    """Attempts to fix UTF-8 mojibake (double-decoded or Latin1/CP1252 misinterpretations)."""
    if not any(c in s for c in 'ÃÂÁÀÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞß'):
        return None
    try:
        fixed = s.encode('latin1').decode('utf-8')
        if fixed != s and all(c.isprintable() or c in '\n\r\t' for c in fixed):
            return fixed
    except Exception:
        pass
    return None


# ─── Candidate Identification Helpers ────────────────────────────────────────

def _is_base64_candidate(s: str) -> bool:
    s_clean = s.strip()
    return len(s_clean) >= 4 and bool(re.match(r'^[A-Za-z0-9+/_\-=]+$', s_clean)) and len(s_clean) % 4 in (0, 2, 3)


def _is_base32_candidate(s: str) -> bool:
    s_clean = s.strip().upper()
    return len(s_clean) >= 8 and bool(re.match(r'^[A-Z2-7=]+$', s_clean))


def _is_hex_candidate(s: str) -> bool:
    cleaned = re.sub(r'[\s,;:\-_\\x0X\[\]\(\)\{\}]+', '', s.strip())
    return len(cleaned) >= 2 and len(cleaned) % 2 == 0 and bool(re.match(r'^[0-9a-fA-F]+$', cleaned))


def _is_binary_candidate(s: str) -> bool:
    cleaned = re.sub(r'[\s,;0b0B]+', '', s.strip())
    return len(cleaned) >= 7 and bool(re.match(r'^[01]+$', cleaned))


def _is_decimal_ascii_candidate(s: str) -> bool:
    tokens = [t.strip() for t in re.split(r'[\s,;\-]+', s.strip()) if t.strip()]
    return len(tokens) >= 3 and all(t.isdigit() for t in tokens)


# ─── Ordered Encoding Pipeline ───────────────────────────────────────────────

ENCODING_DETECTORS = [
    ("Morse Code",                  lambda s: '.' in s or '-' in s,         _try_morse),
    ("Decimal ASCII",              _is_decimal_ascii_candidate,             _try_decimal_ascii),
    ("ASCII / Unicode Escapes",    lambda s: '\\u' in s or '&#' in s or '\\x' in s, _try_unicode_ascii_escapes),
    ("URL Encoding",               lambda s: '%' in s,                     _try_url),
    ("Binary",                     _is_binary_candidate,                   _try_binary),
    ("Hexadecimal",                _is_hex_candidate,                      _try_hex),
    ("Base16",                     lambda s: len(s.strip()) % 2 == 0 and bool(re.match(r'^[0-9A-Fa-f]{4,}$', s.strip())), _try_base16),
    ("Base32",                     _is_base32_candidate,                   _try_base32),
    ("Base64",                     _is_base64_candidate,                   _try_base64),
    ("Base85",                     lambda s: len(s.strip()) >= 5,          _try_base85),
    ("Base58",                     lambda s: len(s.strip()) >= 4,          _try_base58),
    ("UTF-8 Mojibake",             lambda s: any(ord(c) > 127 for c in s), _try_utf8_mojibake),
]


# ─── Hash Detection ──────────────────────────────────────────────────────────

def _detect_hash_algorithms(s: str) -> List[Dict[str, str]]:
    """Return list of possible hash algorithms matching the string fingerprint."""
    s_clean = s.strip()
    matches = []
    seen = set()
    for name, pattern, bits in HASH_PATTERNS:
        if re.match(pattern, s_clean) and name not in seen:
            seen.add(name)
            matches.append({"algorithm": name, "bits": bits})
    return matches


# ─── Single-Layer Detector ───────────────────────────────────────────────────

def _detect_single_layer(text: str) -> Dict[str, Any]:
    """
    Detects and decodes a single layer of text.
    Returns:
        type, encoding, decoded, is_hash, hash_algorithms, confidence, raw
    """
    text_clean = text.strip()
    result: Dict[str, Any] = {
        "type": "unknown",
        "encoding": None,
        "decoded": None,
        "is_hash": False,
        "hash_algorithms": [],
        "confidence": "low",
        "raw": text_clean,
    }

    is_pure_hex = bool(re.match(r'^[a-fA-F0-9]+$', text_clean))
    hash_algos = _detect_hash_algorithms(text_clean) if is_pure_hex else []

    # 1. Try ordered encoding transformations
    for enc_name, condition, decoder in ENCODING_DETECTORS:
        try:
            if not condition(text_clean):
                continue
            decoded = decoder(text_clean)
            if decoded and decoded != text_clean:
                result["type"] = "encoding"
                result["encoding"] = enc_name
                result["decoded"] = decoded
                result["confidence"] = "high"
                if hash_algos:
                    result["possible_hash_algorithms"] = hash_algos
                return result
        except Exception:
            continue

    # 2. Pure Hash verification (hex that cannot be decoded to meaningful text)
    if hash_algos and is_pure_hex:
        result["type"] = "hash"
        result["encoding"] = "Hash (non-reversible)"
        result["is_hash"] = True
        result["hash_algorithms"] = hash_algos
        result["decoded"] = None
        result["confidence"] = "high"
        return result

    # 3. ROT transformations (Caesar shifts 1..25, ROT47)
    rot_res = _try_rot_transformations(text_clean)
    if rot_res:
        decoded_rot, rot_algo = rot_res
        if decoded_rot != text_clean:
            result["type"] = "encoding"
            result["encoding"] = f"ROT Transformation ({rot_algo})"
            result["decoded"] = decoded_rot
            result["confidence"] = "high" if "flag{" in decoded_rot.lower() else "medium"
            return result

    # 4. Plaintext fallback
    result["type"] = "plaintext"
    result["encoding"] = "None (plaintext)"
    result["decoded"] = text_clean
    result["confidence"] = "medium"
    return result


# ─── Public Recursive Decoding Engine ─────────────────────────────────────────

def analyze_hash_or_encoding(text: str, max_layers: int = 15) -> Dict[str, Any]:
    """
    Full recursive multi-layer encoding and hash analysis.
    Iteratively strips and transforms encodings up to `max_layers` deep,
    handling Base64, Base32, Base16, Hex, Binary, URL, Base85, Base58,
    Morse, Decimal ASCII, ROT, and Gzip/Zlib streams.
    """
    original = text.strip()
    layers: List[Dict[str, Any]] = []
    current = original
    seen_hashes = {hashlib.sha256(current.encode('utf-8', errors='ignore')).hexdigest()}

    for layer_num in range(1, max_layers + 1):
        analysis = _detect_single_layer(current)
        analysis["layer"] = layer_num
        layers.append(analysis)

        # Stop if reached plaintext, non-reversible hash, or unknown
        if analysis["type"] in ("plaintext", "hash", "unknown"):
            break

        decoded = analysis.get("decoded")
        if not decoded or decoded == current:
            break

        # Cycle & Infinite Loop Detection
        dec_hash = hashlib.sha256(decoded.encode('utf-8', errors='ignore')).hexdigest()
        if dec_hash in seen_hashes:
            break
        seen_hashes.add(dec_hash)
        current = decoded

        # Short-circuit if a flag is found in intermediate layer
        if re.search(r'(flag\{.*?\}|ctf\{.*?\})', current, re.IGNORECASE):
            next_check = _detect_single_layer(current)
            next_check["layer"] = layer_num + 1
            layers.append(next_check)
            break

        # Check if next step terminates at plaintext
        next_check = _detect_single_layer(current)
        if next_check["type"] in ("plaintext", "unknown"):
            next_check["layer"] = layer_num + 1
            layers.append(next_check)
            break

    encoding_layer_count = sum(1 for l in layers if l.get("type") == "encoding")
    is_multi_encoded = encoding_layer_count >= 2

    # Find final decoded value
    final_decoded: Optional[str] = None
    for l in reversed(layers):
        if l.get("decoded"):
            final_decoded = l["decoded"]
            break

    # Build clear execution summary
    encoding_names = [l["encoding"] for l in layers if l.get("type") == "encoding"]
    hash_algos_flat: List[str] = []
    for l in layers:
        for a in (l.get("hash_algorithms") or []):
            algo = a.get("algorithm", "") if isinstance(a, dict) else str(a)
            if algo not in hash_algos_flat:
                hash_algos_flat.append(algo)

    if hash_algos_flat:
        summary = f"Hash detected: {', '.join(hash_algos_flat[:3])} (non-reversible)"
    elif is_multi_encoded:
        summary = f"Recursive Peel ({encoding_layer_count} layers): {' → '.join(encoding_names)} → plaintext"
    elif encoding_names:
        preview = (final_decoded or '')[:80]
        summary = f"Encoded as {encoding_names[0]} → decoded: {preview}"
    elif layers and layers[0].get("type") == "plaintext":
        summary = "Plaintext — no encoding detected"
    else:
        summary = "Unknown encoding or format"

    return {
        "original": original,
        "is_double_encoded": is_multi_encoded,
        "is_multi_encoded": is_multi_encoded,
        "encoding_layers": layers,
        "final_decoded": final_decoded,
        "total_layers": len(layers),
        "summary": summary,
    }


def extract_encoded_strings(challenge_text: str) -> List[Dict[str, Any]]:
    """
    Scans challenge text for suspicious encoded / hashed substrings.
    Returns list of parsed analysis dicts.
    """
    candidates = set()

    # Quoted strings
    for m in re.finditer(r'"([^"]{4,})"', challenge_text):
        candidates.add(m.group(1))
    for m in re.finditer(r"'([^']{4,})'", challenge_text):
        candidates.add(m.group(1))

    # Hex strings or hashes
    for m in re.finditer(r'\b([a-fA-F0-9]{16,})\b', challenge_text):
        candidates.add(m.group(1))

    # Base64 patterns
    for m in re.finditer(r'([A-Za-z0-9+/]{16,}={0,2})', challenge_text):
        candidates.add(m.group(1))

    # Space-separated decimal numbers (Decimal ASCII)
    for m in re.finditer(r'(\b\d{2,3}(?:[ ,;\-]+\d{2,3}){3,}\b)', challenge_text):
        candidates.add(m.group(1))

    # Whole text candidate
    candidates.add(challenge_text.strip())

    results: List[Dict[str, Any]] = []
    seen = set()
    for cand in candidates:
        cand_clean = cand.strip()
        if cand_clean in seen or len(cand_clean) < 4:
            continue
        seen.add(cand_clean)
        analysis = analyze_hash_or_encoding(cand_clean)
        if analysis["encoding_layers"] and analysis["encoding_layers"][0].get("type") not in ("plaintext", "unknown"):
            results.append(analysis)

    return results


# ─── Self-Test Suite ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import gzip
    import base64

    # Build complex multi-layer challenge
    # Flag: flag{multi_layer_recursive_unpeeled}
    # 1. Decimal ASCII
    s1 = " ".join(str(ord(c)) for c in "flag{multi_layer_recursive_unpeeled}")
    # 2. Hex
    s2 = s1.encode().hex()
    # 3. Gzip
    s3_gz = gzip.compress(s2.encode())
    # 4. Base64
    s4_b64 = base64.b64encode(s3_gz).decode()
    # 5. URL encode
    s5_url = urllib.parse.quote(s4_b64)

    test_vectors = [
        ("Base64",               base64.b64encode(b"flag{b64_test}").decode()),
        ("Base32",               base64.b32encode(b"flag{b32_test}").decode()),
        ("Base16",               base64.b16encode(b"flag{b16_test}").decode()),
        ("Hexadecimal",          b"flag{hex_test}".hex()),
        ("Binary",               " ".join(format(b, "08b") for b in b"flag{bin_test}")),
        ("Decimal ASCII",        " ".join(str(ord(c)) for c in "flag{dec_ascii_test}")),
        ("URL Encoding",         urllib.parse.quote("flag{url_test}")),
        ("Base85 (b85)",         base64.b85encode(b"flag{b85_test}").decode()),
        ("Base85 (Ascii85)",     base64.a85encode(b"flag{a85_test}").decode()),
        ("Morse Code",           ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."),
        ("ROT13",                "synt{ebg13_grfg}"),
        ("ROT47",                "".join(chr(33 + ((ord(c) - 33 + 47) % 94)) for c in "flag{rot47_test}")),
        ("Unicode Escapes",      r"\u0066\u006c\u0061\u0067\u007b\u0075\u006e\u0069\u0063\u006f\u0064\u0065\u007d"),
        ("Gzip in Base64",       base64.b64encode(gzip.compress(b"flag{gzip_zlib_test}")).decode()),
        ("5-Layer Recursive",    s5_url),
    ]

    print("=" * 70)
    print("🔎 hash_decoder.py — Comprehensive Encoding Self-Test")
    print("=" * 70)

    for label, payload in test_vectors:
        res = analyze_hash_or_encoding(payload)
        status = "✅" if res.get("final_decoded") else "❌"
        print(f"\n{status} [{label}]")
        print(f"   Input   : {payload[:65]}{'…' if len(payload)>65 else ''}")
        print(f"   Summary : {res['summary']}")
        print(f"   Layers  : {res['total_layers']} | Multi: {res['is_multi_encoded']}")
        print(f"   Decoded : {str(res['final_decoded'])[:80]}")

    print("\n" + "=" * 70)
    print("All encoding and recursive test vectors evaluated!")
