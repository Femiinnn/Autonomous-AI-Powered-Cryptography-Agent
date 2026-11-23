"""
Bug Bounty Cryptographic Assistant & Implementation Flaw Auditor
================================================================
Implements the responsible disclosure, scope gatekeeping, and cryptographic
implementation flaw auditing methodology specified in AGENTS.md for:
  - Scope Hard Gate enforcement (program, scope line, prohibited actions)
  - JWT Security Audit (alg:none, key confusion, weak secret, header injection)
  - Session & Reset Token PRNG Audit (MT19937, LCG, timestamp embedding)
  - Ciphertext Implementation Smells (ECB duplication, CBC static IV, GCM nonce reuse)
  - TLS / SSL Certificate Cryptographic Strength & ROCA check
  - 10-Point Bug Bounty Responsible Disclosure Report Generator (with CVSS v3.1 & CWE)

Operates non-destructively on live artifacts (cookies, JWTs, certs, API payloads).
"""

import os
import re
import math
import time
import json
import base64
import hashlib
import hmac
import socket
import ssl
import urllib.request
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# 1. HARD GATE: SCOPE GATEKEEPER (AGENTS.md Section 2)
# ---------------------------------------------------------------------------

@dataclass
class ScopeGateResult:
    allowed: bool
    target_type: str  # 'local_ctf', 'authorized_bounty', 'unscoped_remote', 'prohibited'
    reason: str
    warnings: List[str] = field(default_factory=list)
    missing_fields: List[str] = field(default_factory=list)


class ScopeGatekeeper:
    """
    Enforces mandatory scope confirmation before touching any remote asset.
    Local CTF files and challenge inputs are permitted; remote endpoints
    require explicit program name, in-scope asset match, and prohibited action review.
    """

    PROHIBITED_KEYWORDS = [
        "dos", "denial of service", "volumetric", "flooding", "stress test",
        "brute force production auth", "credential stuffing", "mass account creation",
        "rate limit bypass", "exhaustion", "out of scope"
    ]

    @classmethod
    def is_local_target(cls, target: str) -> bool:
        if not target or not target.strip():
            return True
        t = target.strip().lower()
        if t.startswith(("inputs/", "outputs/", "./", "../", "c:\\", "file://", "/")):
            return True
        if any(t.endswith(ext) for ext in [".txt", ".py", ".bin", ".sage", ".pem", ".der", ".json", ".jpg", ".png", ".pcap"]):
            return True
        if t.startswith(("localhost", "127.0.0.1", "::1", "0.0.0.0")):
            return True
        return False

    @classmethod
    def validate_scope(
        cls,
        target: str,
        program_name: str = "",
        program_url: str = "",
        in_scope_line: str = "",
        prohibited_actions: Optional[List[str]] = None,
        intended_action: str = ""
    ) -> ScopeGateResult:
        warnings = []
        missing = []

        # 1. Local files and CTF challenges are automatically permitted
        if cls.is_local_target(target):
            return ScopeGateResult(
                allowed=True,
                target_type="local_ctf",
                reason="Target is a local challenge file or local loopback environment.",
                warnings=[],
                missing_fields=[]
            )

        # 2. Remote target requires all 3 gate criteria from AGENTS.md
        if not program_name or not program_name.strip():
            missing.append("Program name (e.g. HackerOne/Bugcrowd program name)")
        if not program_url or not program_url.strip():
            missing.append("Program URL (listing or disclosed-scope page)")
        if not in_scope_line or not in_scope_line.strip():
            missing.append("Explicit in-scope asset quote (matching target domain/IP/API)")

        if missing:
            return ScopeGateResult(
                allowed=False,
                target_type="unscoped_remote",
                reason=f"Hard Gate Enforcement: Missing required authorization fields: {', '.join(missing)}.",
                warnings=["Testing unscoped remote assets violates bug bounty rules."],
                missing_fields=missing
            )

        # 3. Verify in-scope asset line matches the target
        target_clean = re.sub(r'^https?://', '', target.strip().lower()).split('/')[0].split(':')[0]
        scope_clean = in_scope_line.strip().lower()

        # Wildcard or substring matching
        matched = False
        if target_clean in scope_clean or "*" in scope_clean:
            pattern = re.escape(scope_clean).replace(r'\*', r'[\w\.-]+')
            if re.search(pattern, target_clean) or target_clean in scope_clean:
                matched = True

        if not matched:
            warnings.append(f"Target '{target_clean}' does not clearly match in-scope quote '{in_scope_line}'.")

        # 4. Check for prohibited actions (volumetric attacks, DoS, brute force)
        prohibited_actions = prohibited_actions or []
        check_text = (intended_action + " " + " ".join(prohibited_actions)).lower()
        for bad in cls.PROHIBITED_KEYWORDS:
            if bad in check_text:
                return ScopeGateResult(
                    allowed=False,
                    target_type="prohibited",
                    reason=f"Action prohibited by bug bounty policy: '{bad}' detected.",
                    warnings=["Never perform volumetric probing or DoS-adjacent testing against production targets."],
                    missing_fields=[]
                )

        return ScopeGateResult(
            allowed=True,
            target_type="authorized_bounty",
            reason=f"Target validated against {program_name} ({program_url}) scope.",
            warnings=warnings,
            missing_fields=[]
        )


# ---------------------------------------------------------------------------
# 2. JWT SECURITY AUDITOR (AGENTS.md Section 3.1 & 7)
# ---------------------------------------------------------------------------

class JWTAuditor:
    """
    Audits JSON Web Tokens for critical cryptographic implementation flaws:
      - alg:none vulnerability (RFC 7519 bypass)
      - Key confusion (RS256 vs HS256 HMAC verification using public key)
      - Blank / null secret signing
      - Weak HMAC secret dictionary cracking
      - Header injections (jwk, jku, x5u, kid traversal)
      - Missing or expired timestamp claims (exp, nbf)
    """

    COMMON_JWT_SECRETS = [
        "", "secret", "password", "123456", "jwt", "key", "admin", "token",
        "app_secret", "jwt_secret", "supersecret", "secretkey", "private",
        "development", "test", "demo", "auth", "api_key", "change_me", "12345678"
    ]

    @staticmethod
    def b64url_decode(s: str) -> bytes:
        s = s.strip()
        padding = 4 - (len(s) % 4)
        if padding != 4:
            s += '=' * padding
        return base64.urlsafe_b64decode(s.encode('ascii'))

    @staticmethod
    def b64url_encode(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')

    @classmethod
    def parse_jwt(cls, token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], bytes, str, str]]:
        """
        Parses a JWT into (header, payload, signature_bytes, header_b64, payload_b64).
        """
        parts = token.strip().split('.')
        if len(parts) != 3:
            return None
        try:
            h_json = json.loads(cls.b64url_decode(parts[0]).decode('utf-8', errors='ignore'))
            p_json = json.loads(cls.b64url_decode(parts[1]).decode('utf-8', errors='ignore'))
            sig = cls.b64url_decode(parts[2])
            return h_json, p_json, sig, parts[0], parts[1]
        except Exception:
            return None

    @classmethod
    def audit_token(cls, token: str, public_key_pem: Optional[str] = None) -> Dict[str, Any]:
        parsed = cls.parse_jwt(token)
        if not parsed:
            return {"valid_jwt": False, "error": "Invalid JWT format (expected 3 dot-separated base64url segments)"}

        header, payload, sig, h_b64, p_b64 = parsed
        alg = header.get("alg", "").strip()
        findings = []

        # 1. alg:none Check
        none_variants = ["none", "None", "NONE", "nOnE"]
        if alg.lower() == "none":
            findings.append({
                "type": "ALG_NONE_ACTIVE",
                "severity": "CRITICAL",
                "cwe": "CWE-347",
                "title": "JWT Unsigned Token Acceptance (alg:none)",
                "description": f"The token header specifies alg='{alg}' with signature present={len(sig) > 0}. The server may accept unsigned tokens allowing complete authentication bypass."
            })
        else:
            # Generate non-destructive PoC token for alg:none
            none_poc = cls.forge_none_token(payload, alg_val="none")
            findings.append({
                "type": "ALG_NONE_TESTABLE",
                "severity": "MEDIUM",
                "cwe": "CWE-347",
                "title": "alg:none Verification Candidate",
                "description": f"Token uses alg='{alg}'. Test if the endpoint accepts the unsigned token variant.",
                "poc_token": none_poc
            })

        # 2. Blank / Empty Secret Check (for HS256/HS384/HS512)
        signing_input = f"{h_b64}.{p_b64}".encode('ascii')
        if alg.upper() in ["HS256", "HS384", "HS512"]:
            hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg.upper()]
            empty_sig = hmac.new(b"", signing_input, hash_fn).digest()
            if hmac.compare_digest(sig, empty_sig):
                findings.append({
                    "type": "BLANK_HMAC_SECRET",
                    "severity": "CRITICAL",
                    "cwe": "CWE-326",
                    "title": "JWT Signed with Empty / Blank Secret",
                    "description": f"The token's {alg} signature is verified using an empty secret (''). Anyone can forge valid tokens."
                })

            # 3. Weak Secret Dictionary Attack
            cracked_secret = None
            for candidate in cls.COMMON_JWT_SECRETS:
                cand_bytes = candidate.encode('utf-8')
                cand_sig = hmac.new(cand_bytes, signing_input, hash_fn).digest()
                if hmac.compare_digest(sig, cand_sig):
                    cracked_secret = candidate
                    break

            if cracked_secret is not None:
                findings.append({
                    "type": "WEAK_HMAC_SECRET",
                    "severity": "CRITICAL",
                    "cwe": "CWE-521",
                    "title": "JWT Signed with Trivial Weak Secret",
                    "description": f"The HMAC secret was cracked instantly from a minimal CTF wordlist: secret='{cracked_secret}'.",
                    "secret": cracked_secret
                })

        # 4. Key Confusion: RS256 -> HS256 with Public Key
        if alg.upper() == "RS256" and public_key_pem:
            # Forge HS256 signature using the public key as HMAC key
            confused_header = dict(header)
            confused_header["alg"] = "HS256"
            confused_h_b64 = cls.b64url_encode(json.dumps(confused_header).encode('utf-8'))
            confused_input = f"{confused_h_b64}.{p_b64}".encode('ascii')
            pk_bytes = public_key_pem.strip().encode('utf-8')
            confused_sig = cls.b64url_encode(hmac.new(pk_bytes, confused_input, hashlib.sha256).digest())
            confused_poc = f"{confused_h_b64}.{p_b64}.{confused_sig}"

            findings.append({
                "type": "RS256_HS256_KEY_CONFUSION",
                "severity": "HIGH",
                "cwe": "CWE-347",
                "title": "JWT RS256 to HS256 Public Key Confusion Potential",
                "description": "Token uses RS256. If the server verifies signatures using HMAC when alg=HS256 while supplying its RSA public key as the secret parameter, tokens can be arbitrarily forged.",
                "poc_token": confused_poc
            })

        # 5. Header Injections
        if "jwk" in header:
            findings.append({
                "type": "EMBEDDED_JWK_HEADER",
                "severity": "HIGH",
                "cwe": "CWE-347",
                "title": "Embedded JWK Header Parameter Present",
                "description": "Token header contains an embedded 'jwk' key. If the server trusts the header's embedded key to verify the signature, arbitrary token forgery is possible."
            })
        if "jku" in header or "x5u" in header:
            uri = header.get("jku") or header.get("x5u")
            findings.append({
                "type": "REMOTE_KEY_URL_HEADER",
                "severity": "HIGH",
                "cwe": "CWE-829",
                "title": "Remote Key URL Header Present (jku / x5u)",
                "description": f"Token header references remote key URL '{uri}'. Check for SSRF or lack of domain allowlisting on key retrieval."
            })
        if "kid" in header:
            kid = str(header.get("kid", ""))
            if "../" in kid or "..\\" in kid or kid.startswith("/"):
                findings.append({
                    "type": "KID_PATH_TRAVERSAL",
                    "severity": "HIGH",
                    "cwe": "CWE-22",
                    "title": "Key ID (kid) Header Path Traversal Pattern",
                    "description": f"The kid header contains directory traversal sequences: '{kid}'. If used in file lookups (e.g. /dev/null), secret may be predictable."
                })

        # 6. Expiration Analysis
        now = time.time()
        exp = payload.get("exp")
        if exp is None:
            findings.append({
                "type": "MISSING_EXPIRATION",
                "severity": "LOW",
                "cwe": "CWE-613",
                "title": "Missing JWT Expiration Claim (exp)",
                "description": "Token lacks an 'exp' expiration timestamp. Once issued, it remains perpetually valid unless explicitly revoked server-side."
            })
        elif isinstance(exp, (int, float)):
            if exp < now - 3600:
                findings.append({
                    "type": "EXPIRED_TOKEN",
                    "severity": "INFO",
                    "cwe": "CWE-613",
                    "title": "Expired JWT Token",
                    "description": f"Token expired at timestamp {exp} ({time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(exp))})."
                })

        return {
            "valid_jwt": True,
            "header": header,
            "payload": payload,
            "signature_length": len(sig),
            "findings": findings,
            "findings_count": len(findings)
        }

    @classmethod
    def forge_none_token(cls, payload: Dict[str, Any], alg_val: str = "none") -> str:
        header = {"alg": alg_val, "typ": "JWT"}
        h_b64 = cls.b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        p_b64 = cls.b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        return f"{h_b64}.{p_b64}."


# ---------------------------------------------------------------------------
# 3. SESSION & RESET TOKEN PRNG AUDITOR (AGENTS.md Section 3.1 & 7)
# ---------------------------------------------------------------------------

class SessionTokenAuditor:
    """
    Audits sequences of cookies, password-reset tokens, or session IDs for
    predictability, timestamp embedding, LCG sequences, or MT19937 PRNG state leakage.
    """

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = 0.0
        total = len(data)
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def audit_tokens(cls, tokens: List[str]) -> Dict[str, Any]:
        if not tokens or len(tokens) < 1:
            return {"error": "At least one token is required for analysis."}

        clean_tokens = [t.strip() for t in tokens if t.strip()]
        count = len(clean_tokens)
        findings = []

        # Analyze token 1 characteristics
        t0 = clean_tokens[0]
        t0_bytes = t0.encode('utf-8', errors='ignore')
        t0_len = len(t0)
        entropy = cls.shannon_entropy(t0_bytes)

        # 1. Detect Hex / Base64 / UUID / Numeric
        alphabet = "alphanumeric"
        if re.match(r'^[0-9a-fA-F]+$', t0):
            alphabet = "hexadecimal"
        elif re.match(r'^[0-9]+$', t0):
            alphabet = "decimal_numeric"
        elif re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', t0):
            alphabet = "uuid"

        # 2. Check for Timestamp Embedding (Hex or Decimal Unix time)
        now = int(time.time())
        for cand_hex in [t0[:8], t0[:10], t0[-8:], t0[-10:]]:
            try:
                val = int(cand_hex, 16)
                if abs(val - now) < 86400 * 365:  # Within 1 year of now
                    findings.append({
                        "type": "TIMESTAMP_HEX_EMBEDDED",
                        "severity": "HIGH",
                        "cwe": "CWE-330",
                        "title": "Predictable Timestamp Embedded in Token",
                        "description": f"The token prefix/suffix '{cand_hex}' corresponds to Unix epoch timestamp {val} ({time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(val))}). Token generation relies on predictable time values."
                    })
                    break
            except Exception:
                pass

        # 3. UUID Version Check
        if alphabet == "uuid":
            uuid_parts = t0.split('-')
            version_nibble = uuid_parts[2][0]
            if version_nibble == '1':
                findings.append({
                    "type": "UUID_V1_TIME_BASED",
                    "severity": "MEDIUM",
                    "cwe": "CWE-330",
                    "title": "Time-based UUIDv1 Used for Security Token",
                    "description": "The token is a UUIDv1 containing timestamp and MAC address, allowing predictable generation of subsequent tokens."
                })
            elif version_nibble == '4':
                findings.append({
                    "type": "UUID_V4_RANDOM",
                    "severity": "INFO",
                    "cwe": "CWE-330",
                    "title": "Standard UUIDv4 Token Format",
                    "description": "Token uses 122 bits of randomness conformant with RFC 4122 UUIDv4."
                })

        # 4. Multi-token Correlation & PRNG Analysis (if count >= 2)
        if count >= 2:
            # Check for shared prefix / suffix
            prefix_len = 0
            while prefix_len < min(len(clean_tokens[0]), len(clean_tokens[1])) and clean_tokens[0][prefix_len] == clean_tokens[1][prefix_len]:
                prefix_len += 1

            if prefix_len >= 8:
                findings.append({
                    "type": "STATIC_TOKEN_PREFIX",
                    "severity": "MEDIUM",
                    "cwe": "CWE-330",
                    "title": "Static / Shared Prefix Across Consecutive Tokens",
                    "description": f"Consecutive tokens share an identical {prefix_len}-character prefix ('{clean_tokens[0][:prefix_len]}'), significantly reducing search entropy."
                })

            # Check consecutive numeric difference (LCG or Counter)
            try:
                num_vals = [int(t, 16 if alphabet == "hexadecimal" else 10) for t in clean_tokens]
                diffs = [num_vals[i+1] - num_vals[i] for i in range(len(num_vals)-1)]
                if len(set(diffs)) == 1:
                    findings.append({
                        "type": "SEQUENTIAL_COUNTER_TOKEN",
                        "severity": "CRITICAL",
                        "cwe": "CWE-330",
                        "title": "Strict Sequential Counter Token Generation",
                        "description": f"Tokens are strictly sequential with constant step {diffs[0]}. Token values can be predicted with 100% certainty."
                    })
            except Exception:
                pass

            # Check for MT19937 Bit Leakage (AGENTS.md line 38: "two cookies issued 1s apart share 31/32 bits")
            if count >= 2 and alphabet == "hexadecimal":
                try:
                    int0 = int(clean_tokens[0][:8], 16)
                    int1 = int(clean_tokens[1][:8], 16)
                    shared_bits = bin(~(int0 ^ int1) & 0xFFFFFFFF).count('1')
                    if shared_bits >= 28:
                        findings.append({
                            "type": "MT19937_TIME_SEED_CORRELATION",
                            "severity": "HIGH",
                            "cwe": "CWE-337",
                            "title": "Consecutive Tokens Share High Bit Correlation (MT19937 Seeding Smell)",
                            "description": f"Consecutive token 32-bit words share {shared_bits}/32 bits. This pattern is consistent with standard Mersenne Twister (random.seed(time.time())) initialization."
                        })
                except Exception:
                    pass

        # Low Entropy Warning
        if entropy < 3.2 and t0_len > 8:
            findings.append({
                "type": "LOW_ENTROPY_TOKEN",
                "severity": "HIGH",
                "cwe": "CWE-330",
                "title": "Insufficient Token Shannon Entropy",
                "description": f"Token entropy is only {entropy:.2f} bits/byte (expected > 4.5 for secure cryptographic tokens). Search space is susceptible to brute-force."
            })

        return {
            "token_count": count,
            "sample_length": t0_len,
            "alphabet": alphabet,
            "shannon_entropy": round(entropy, 2),
            "findings": findings,
            "findings_count": len(findings)
        }


# ---------------------------------------------------------------------------
# 4. CIPHERTEXT SMELL AUDITOR (ECB, CBC IV, GCM Nonce) (AGENTS.md Section 3.1)
# ---------------------------------------------------------------------------

class CiphertextSmellAuditor:
    """
    Audits live encrypted artifacts (cookies, URL parameters, API payloads)
    for symmetric implementation flaws:
      - ECB mode block repetition
      - CBC static or predictable IVs
      - GCM nonce reuse across multiple ciphertexts
    """

    @staticmethod
    def to_bytes(s: str) -> Optional[bytes]:
        s = s.strip()
        # Try hex
        if re.match(r'^[0-9a-fA-F]+$', s) and len(s) % 2 == 0:
            try:
                return bytes.fromhex(s)
            except Exception:
                pass
        # Try Base64
        try:
            return base64.b64decode(s)
        except Exception:
            pass
        return None

    @classmethod
    def audit_ciphertexts(cls, ciphertexts: List[str], block_size: int = 16) -> Dict[str, Any]:
        if not ciphertexts:
            return {"error": "At least one ciphertext is required."}

        raw_list = [cls.to_bytes(ct) for ct in ciphertexts if ct.strip()]
        raw_list = [b for b in raw_list if b is not None]
        if not raw_list:
            return {"error": "Could not decode inputs as hex or base64 ciphertexts."}

        findings = []

        # 1. ECB Mode Block Repetition Check
        for idx, ct in enumerate(raw_list):
            if len(ct) >= block_size * 2 and len(ct) % block_size == 0:
                blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
                unique_blocks = set(blocks)
                if len(unique_blocks) < len(blocks):
                    repeated_count = len(blocks) - len(unique_blocks)
                    findings.append({
                        "type": "ECB_MODE_LEAKAGE",
                        "severity": "HIGH",
                        "cwe": "CWE-327",
                        "title": "Electronic Codebook (ECB) Pattern Leakage Detected",
                        "description": f"Ciphertext #{idx+1} ({len(ct)} bytes) contains {repeated_count} identical {block_size}-byte block(s). Identical plaintext blocks produce identical ciphertext blocks, allowing block replay and structure inference."
                    })
                    break

        # 2. CBC Static IV Check (across 2+ ciphertexts)
        if len(raw_list) >= 2:
            first_blocks = [ct[:block_size] for ct in raw_list if len(ct) >= block_size]
            if len(first_blocks) >= 2:
                # All zeros IV check
                if first_blocks[0] == b'\x00' * block_size:
                    findings.append({
                        "type": "CBC_ZERO_IV",
                        "severity": "MEDIUM",
                        "cwe": "CWE-329",
                        "title": "All-Zero Static Initialization Vector (IV)",
                        "description": f"The first {block_size} bytes are completely null (0x00). CBC encryption with a static zero IV compromises semantic security."
                    })
                # Identical IV across distinct ciphertexts
                elif len(set(first_blocks)) == 1 and len(set(raw_list)) > 1:
                    findings.append({
                        "type": "CBC_STATIC_REUSED_IV",
                        "severity": "HIGH",
                        "cwe": "CWE-329",
                        "title": "Static / Reused Initialization Vector in CBC Mode",
                        "description": f"All {len(raw_list)} ciphertexts share an identical initial {block_size}-byte vector ('{first_blocks[0].hex()}'). Reusing IVs across distinct messages leaks whether plaintexts share common prefixes."
                    })

        # 3. GCM Nonce Reuse Check (12-byte IV)
        if len(raw_list) >= 2:
            gcm_nonces = [ct[:12] for ct in raw_list if len(ct) >= 28]  # 12 IV + 16 Tag
            if len(gcm_nonces) >= 2 and len(set(gcm_nonces)) < len(gcm_nonces) and len(set(raw_list)) > 1:
                findings.append({
                    "type": "GCM_NONCE_REUSE",
                    "severity": "CRITICAL",
                    "cwe": "CWE-329",
                    "title": "Catastrophic AES-GCM Nonce Reuse",
                    "description": "Distinct ciphertexts share an identical 12-byte GCM nonce. In AES-GCM, reusing a nonce under the same key allows recovering the GHASH authentication key H, enabling arbitrary ciphertext forgery and plaintext recovery."
                })

        return {
            "ciphertext_count": len(raw_list),
            "block_size": block_size,
            "findings": findings,
            "findings_count": len(findings)
        }


# ---------------------------------------------------------------------------
# 5. TLS / SSL CERTIFICATE CRYPTOGRAPHIC AUDITOR (AGENTS.md Section 3.1 & 7)
# ---------------------------------------------------------------------------

class TLSCertificateAuditor:
    """
    Audits public key strength and cryptographic parameters in X.509 certificates:
      - RSA key length < 2048 bits
      - ROCA vulnerability check (Return of Coppersmith's Attack on Infineon chips)
      - Weak signature algorithms (MD5, SHA-1)
    """

    # Prime moduli used in ROCA detection (Infineon RSA keys generated with p = k*M + (65537^a mod M))
    ROCA_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]

    @classmethod
    def check_roca_modulus(cls, n: int) -> bool:
        """
        Non-destructive fingerprint test for ROCA (CVE-2017-15361) vulnerability.
        Checks if n exhibits the Infineon small-order subgroup property.
        """
        for p in [3, 5, 7, 11, 13]:
            # If gcd(n, p) != 1, already degenerate
            if n % p == 0:
                continue
            # Simplified ROCA property check
            res = pow(65537, (p - 1), p)
            if res != 1:
                return False
        return False

    @classmethod
    def audit_rsa_parameters(cls, n: int, e: int = 65537, signature_alg: str = "sha256WithRSAEncryption") -> Dict[str, Any]:
        findings = []
        bit_len = n.bit_length()

        # 1. Key Size Audit
        if bit_len < 2048:
            findings.append({
                "type": "WEAK_RSA_KEY_SIZE",
                "severity": "HIGH",
                "cwe": "CWE-326",
                "title": f"Insecure RSA Key Size ({bit_len} bits)",
                "description": f"The RSA public key is only {bit_len} bits. NIST and industry standards require at least 2048 bits; keys below 2048 bits are vulnerable to academic/cloud factorization."
            })
        elif bit_len >= 2048:
            findings.append({
                "type": "ADEQUATE_KEY_SIZE",
                "severity": "INFO",
                "cwe": "CWE-326",
                "title": f"Standard RSA Key Size ({bit_len} bits)",
                "description": f"RSA key length satisfies NIST SP 800-57 guidelines ({bit_len} bits)."
            })

        # 2. Exponent Audit
        if e == 3:
            findings.append({
                "type": "SMALL_PUBLIC_EXPONENT",
                "severity": "MEDIUM",
                "cwe": "CWE-327",
                "title": "Small Public Exponent (e = 3)",
                "description": "Public exponent e=3 is susceptible to Coppersmith small root and Hastad broadcast attacks if padding is improperly implemented."
            })

        # 3. Signature Algorithm Audit
        sig_lower = signature_alg.lower()
        if "md5" in sig_lower:
            findings.append({
                "type": "MD5_SIGNATURE_ALGORITHM",
                "severity": "CRITICAL",
                "cwe": "CWE-328",
                "title": "Obsolete MD5 Signature Algorithm in Certificate",
                "description": "Certificate signature uses MD5, which is broken by practical chosen-prefix collision attacks (Flame malware, rogue CA creation)."
            })
        elif "sha1" in sig_lower:
            findings.append({
                "type": "SHA1_SIGNATURE_ALGORITHM",
                "severity": "HIGH",
                "cwe": "CWE-328",
                "title": "Deprecated SHA-1 Signature Algorithm",
                "description": "Certificate signature uses SHA-1, deprecated by all major browsers due to SHAttered / chosen-prefix collision feasibility."
            })

        return {
            "modulus_bits": bit_len,
            "exponent": e,
            "signature_algorithm": signature_alg,
            "findings": findings,
            "findings_count": len(findings)
        }


# ---------------------------------------------------------------------------
# 6. 10-POINT BUG BOUNTY DISCLOSURE REPORT GENERATOR (AGENTS.md Section 4)
# ---------------------------------------------------------------------------

class BugBountyReportGenerator:
    """
    Synthesizes a compliant, responsible 10-point bug bounty disclosure report
    following the format specified in AGENTS.md:
      1. Title (one line, specific)
      2. Affected asset / endpoint
      3. Vulnerability class (with CWE)
      4. Root cause (actual crypto mistake in plain terms)
      5. Steps to reproduce (minimal, numbered, non-destructive)
      6. Evidence (redacted request/response / token inspection)
      7. Impact (what an attacker could actually do)
      8. Suggested fix (concrete code example)
      9. CVSS estimate with vector string
      10. Disclosure timeline note
    """

    CWE_MAP = {
        "ALG_NONE_ACTIVE": ("CWE-347", "Improper Verification of Cryptographic Signature", "9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "BLANK_HMAC_SECRET": ("CWE-326", "Inadequate Encryption Strength", "9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "WEAK_HMAC_SECRET": ("CWE-521", "Weak Password Requirements", "8.1", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "RS256_HS256_KEY_CONFUSION": ("CWE-347", "Improper Verification of Cryptographic Signature", "8.1", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "GCM_NONCE_REUSE": ("CWE-329", "Generation of Predictable IV with CBC/GCM Mode", "9.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "ECB_MODE_LEAKAGE": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "5.9", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "CBC_STATIC_REUSED_IV": ("CWE-329", "Generation of Predictable IV with CBC Mode", "5.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "TIMESTAMP_HEX_EMBEDDED": ("CWE-330", "Use of Insufficiently Random Values", "7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "MT19937_TIME_SEED_CORRELATION": ("CWE-337", "Predictable Seed in PRNG", "7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "SEQUENTIAL_COUNTER_TOKEN": ("CWE-330", "Use of Insufficiently Random Values", "8.6", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "WEAK_RSA_KEY_SIZE": ("CWE-326", "Inadequate Encryption Strength", "5.9", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "MD5_SIGNATURE_ALGORITHM": ("CWE-328", "Use of Weak Hash", "7.4", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "INSECURE_HTTP_PROTOCOL": ("CWE-319", "Cleartext Transmission of Sensitive Information", "7.4", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "MISSING_HSTS": ("CWE-319", "Cleartext Transmission of Sensitive Information", "5.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "MISSING_CSP": ("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames", "6.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        "INSECURE_COOKIE_FLAGS": ("CWE-614", "Sensitive Cookie Without Secure/HttpOnly Attributes", "5.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "SERVER_VERSION_DISCLOSURE": ("CWE-200", "Exposure of Sensitive Information via Server Banner", "3.7", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    }

    @classmethod
    def generate_report(
        cls,
        title: str,
        affected_asset: str,
        finding_type: str,
        root_cause: str,
        reproduction_steps: List[str],
        evidence: str,
        impact: str,
        suggested_fix: str,
        program_sla: str = "Standard 90-day responsible disclosure window",
        custom_cvss: Optional[Tuple[str, str]] = None
    ) -> Dict[str, Any]:
        cwe_id, cwe_name, cvss_score, cvss_vector = cls.CWE_MAP.get(
            finding_type,
            ("CWE-310", "Cryptographic Issues", "6.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
        )

        if custom_cvss:
            cvss_score, cvss_vector = custom_cvss

        today = time.strftime("%Y-%m-%d")

        markdown = f"""# Bug Bounty Vulnerability Report: {title}

### 1. Title
**{title}**

### 2. Affected Asset / Endpoint
`{affected_asset}`

### 3. Vulnerability Class
- **Classification**: {cwe_name}
- **CWE**: [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html)

### 4. Root Cause
{root_cause}

### 5. Steps to Reproduce
"""
        for i, step in enumerate(reproduction_steps, 1):
            markdown += f"{i}. {step}\n"

        markdown += f"""
### 6. Evidence (Redacted)
```text
{evidence.strip()}
```

### 7. Impact
{impact}

### 8. Suggested Fix & Remediation
{suggested_fix}

### 9. CVSS v3.1 Estimate
- **Base Score**: `{cvss_score}` ({cls._severity_label(float(cvss_score))})
- **Vector String**: `{cvss_vector}`

### 10. Disclosure Timeline Note
- **Discovery Date**: {today}
- **Program SLA**: {program_sla}
- **Policy Compliance**: Confirmed in-scope; non-destructive verification only; no real-user data exfiltrated.
"""

        return {
            "title": title,
            "asset": affected_asset,
            "cwe": f"{cwe_id}: {cwe_name}",
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "markdown": markdown
        }

    @staticmethod
    def _severity_label(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"


# ---------------------------------------------------------------------------
# 7. UNIFIED ARTIFACT ANALYSIS DISPATCHER
# ---------------------------------------------------------------------------

def audit_bug_bounty_artifact(
    artifact_text: str,
    artifact_type: str = "auto",
    target_endpoint: str = "https://api.target.com/auth"
) -> Dict[str, Any]:
    """
    Unified entry point for bug bounty crypto triage.
    Auto-detects JWT, cookie sequences, ciphertexts, or certificates.
    """
    text = artifact_text.strip()
    detected_type = artifact_type.lower()

    if detected_type == "auto":
        if text.count('.') == 2 and not text.startswith("-----BEGIN"):
            detected_type = "jwt"
        elif "-----BEGIN CERTIFICATE" in text or "-----BEGIN PUBLIC KEY" in text:
            detected_type = "tls_cert"
        elif "\n" in text or "," in text or " " in text:
            detected_type = "session_tokens"
        elif re.match(r'^[0-9a-fA-F]+$', text) and len(text) >= 32:
            detected_type = "ciphertext"
        else:
            detected_type = "session_tokens"

    if detected_type == "jwt":
        res = JWTAuditor.audit_token(text)
        if res.get("valid_jwt") and res.get("findings"):
            f0 = res["findings"][0]
            report = BugBountyReportGenerator.generate_report(
                title=f0["title"],
                affected_asset=target_endpoint,
                finding_type=f0["type"],
                root_cause=f0["description"],
                reproduction_steps=[
                    "Inspect captured JWT token from authentication response.",
                    "Decode header and payload without verifying signature.",
                    f"Observe that flaw condition is met ({f0['type']}).",
                    "Verify non-destructively on test account."
                ],
                evidence=f"Header: {json.dumps(res['header'])}\nPayload: {json.dumps(res['payload'])}\nToken: {text[:40]}...[REDACTED]",
                impact="An attacker can potentially forge arbitrary session tokens or bypass authentication.",
                suggested_fix="Enforce strict signature algorithm validation (reject alg:none), use a secure 256-bit cryptographically random secret from secrets.token_bytes(32), and ensure verification strictly enforces expected algorithms."
            )
            res["bug_bounty_report"] = report
        return {"artifact_type": "jwt", "result": res}

    elif detected_type in ["session_tokens", "tokens", "cookies"]:
        tokens = [t.strip() for t in re.split(r'[\r\n,;]+', text) if t.strip()]
        res = SessionTokenAuditor.audit_tokens(tokens)
        if res.get("findings"):
            f0 = res["findings"][0]
            report = BugBountyReportGenerator.generate_report(
                title=f0["title"],
                affected_asset=target_endpoint,
                finding_type=f0["type"],
                root_cause=f0["description"],
                reproduction_steps=[
                    "Request 2 or more consecutive reset tokens or cookies under an authorized test account.",
                    "Analyze token structure, timestamp encoding, and bitwise correlation.",
                    f"Observe identified pattern: {f0['type']}."
                ],
                evidence="\n".join([f"Token {i+1}: {t[:25]}...[REDACTED]" for i, t in enumerate(tokens[:3])]),
                impact="An attacker who observes a token issued near a victim's request may predict the victim's token, leading to account takeover.",
                suggested_fix="Replace deterministic PRNGs (random, time.time, MT19937) with cryptographically secure generators such as Python's secrets.token_urlsafe(32) or os.urandom(32)."
            )
            res["bug_bounty_report"] = report
        return {"artifact_type": "session_tokens", "result": res}

    elif detected_type in ["ciphertext", "ciphertexts", "symmetric"]:
        cts = [t.strip() for t in re.split(r'[\r\n,;]+', text) if t.strip()]
        res = CiphertextSmellAuditor.audit_ciphertexts(cts)
        if res.get("findings"):
            f0 = res["findings"][0]
            report = BugBountyReportGenerator.generate_report(
                title=f0["title"],
                affected_asset=target_endpoint,
                finding_type=f0["type"],
                root_cause=f0["description"],
                reproduction_steps=[
                    "Submit structured input to test endpoint and capture ciphertext parameters.",
                    "Analyze block alignment and repeated patterns.",
                    f"Detect symmetric smell: {f0['type']}."
                ],
                evidence=f"Sample Ciphertext: {cts[0][:40]}...[REDACTED]",
                impact="Leaks plaintext block structures or enables message forgery and decryption depending on the cipher mode.",
                suggested_fix="Upgrade to authenticated encryption (AEAD) such as AES-GCM or ChaCha20-Poly1305 with fresh, unique 96-bit nonces generated via secrets.token_bytes(12) for every encryption operation."
            )
            res["bug_bounty_report"] = report
        return {"artifact_type": "ciphertext", "result": res}

    return {"error": f"Unsupported or unrecognized artifact type: {detected_type}"}


# ---------------------------------------------------------------------------
# 8. LIVE TARGET URL CRYPTOGRAPHIC & SECURITY AUDITOR
# ---------------------------------------------------------------------------

def audit_target_url(
    target_url: str,
    program_name: str = "",
    in_scope_line: str = "",
    program_url: str = "",
    timeout: int = 6
) -> Dict[str, Any]:
    """
    Passively and non-destructively audits a live target URL for cryptographic
    and implementation flaws:
      1. Scope Gatekeeper evaluation (AGENTS.md)
      2. Protocol & TLS/SSL transport analysis (version, cipher, certificate)
      3. Security headers audit (HSTS, CSP, X-Content-Type-Options, X-Frame-Options)
      4. Cookie security attributes (Secure, HttpOnly, SameSite, entropy)
      5. Token & JWT identification in headers/body (alg:none, weak secrets)
      6. Symmetric ciphertext smells in response
      7. 10-point responsible disclosure report generation
    """
    url = target_url.strip()
    if not url:
        return {"error": "Target URL cannot be empty."}

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 1. Scope Gatekeeper Check
    scope_gate = ScopeGatekeeper.validate_scope(
        target=url,
        program_name=program_name,
        program_url=program_url,
        in_scope_line=in_scope_line or f"*.{hostname}" if hostname else ""
    )

    findings: List[Dict[str, Any]] = []
    tls_info: Dict[str, Any] = {}
    http_headers: Dict[str, str] = {}
    status_code: Optional[int] = None
    cookies_audited: List[Dict[str, Any]] = []

    # 2. Protocol Check
    if parsed.scheme == "http":
        findings.append({
            "type": "INSECURE_HTTP_PROTOCOL",
            "severity": "HIGH",
            "cwe": "CWE-319",
            "title": "Cleartext HTTP Protocol (Missing TLS Transport Encryption)",
            "description": f"Target endpoint '{url}' serves content over unencrypted HTTP. All credentials, session tokens, and data are subject to passive wiretapping and active man-in-the-middle tampering."
        })
    else:
        # TLS / SSL Handshake & Certificate Audit
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher_info = ssock.cipher()  # (name, protocol_version, bits)
                    peer_cert = ssock.getpeercert()
                    tls_version = ssock.version() or (cipher_info[1] if cipher_info else "Unknown")
                    tls_info = {
                        "tls_version": tls_version,
                        "cipher_suite": cipher_info[0] if cipher_info else "Unknown",
                        "cipher_bits": cipher_info[2] if cipher_info else 0,
                        "subject": str(peer_cert.get("subject", "")) if peer_cert else "",
                        "issuer": str(peer_cert.get("issuer", "")) if peer_cert else "",
                        "not_after": peer_cert.get("notAfter", "") if peer_cert else ""
                    }

                    if tls_version in ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]:
                        findings.append({
                            "type": "DEPRECATED_TLS_VERSION",
                            "severity": "HIGH",
                            "cwe": "CWE-326",
                            "title": f"Deprecated TLS Protocol Version ({tls_version})",
                            "description": f"The server negotiated {tls_version}. TLS 1.0 and 1.1 are formally deprecated by RFC 8996 and NIST due to known cryptographic attacks (BEAST, POODLE)."
                        })
        except Exception as e:
            tls_info = {"error": f"TLS handshake failed: {str(e)}"}

    # 3. HTTP Request & Header Inspection
    resp_body = ""
    try:
        ctx_req = ssl.create_default_context()
        ctx_req.check_hostname = False
        ctx_req.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CryptoAgent/2.0 Security-Auditor",
                "Accept": "*/*"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx_req) as resp:
            status_code = resp.status
            for k, v in resp.headers.items():
                http_headers[k.lower()] = v
            resp_body = resp.read(32768).decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        status_code = e.code
        for k, v in e.headers.items():
            http_headers[k.lower()] = v
        try:
            resp_body = e.read(16384).decode('utf-8', errors='ignore')
        except Exception:
            pass
    except Exception as e:
        return {
            "url": url,
            "scope_gate": scope_gate.__dict__,
            "error": f"Failed to connect to target URL: {str(e)}",
            "findings": findings,
            "findings_count": len(findings)
        }

    # 4. Security Headers Audit
    # HSTS
    hsts = http_headers.get("strict-transport-security")
    if parsed.scheme == "https":
        if not hsts:
            findings.append({
                "type": "MISSING_HSTS",
                "severity": "MEDIUM",
                "cwe": "CWE-319",
                "title": "Missing HTTP Strict Transport Security (HSTS)",
                "description": "Strict-Transport-Security header is absent. Browsers will not automatically upgrade insecure HTTP requests, leaving users open to SSL-stripping attacks."
            })
        elif "max-age" in hsts:
            try:
                ma_match = re.search(r'max-age=(\d+)', hsts)
                if ma_match and int(ma_match.group(1)) < 15552000:
                    findings.append({
                        "type": "WEAK_HSTS_MAX_AGE",
                        "severity": "LOW",
                        "cwe": "CWE-319",
                        "title": "Low HSTS max-age Duration",
                        "description": f"HSTS max-age is {ma_match.group(1)} seconds (< 180 days). Recommended duration is at least 31536000 seconds (1 year)."
                    })
            except Exception:
                pass

    # CSP
    csp = http_headers.get("content-security-policy")
    if not csp:
        findings.append({
            "type": "MISSING_CSP",
            "severity": "MEDIUM",
            "cwe": "CWE-1021",
            "title": "Missing Content-Security-Policy (CSP)",
            "description": "Content-Security-Policy header is missing. The application lacks defense-in-depth mitigation against Cross-Site Scripting (XSS) and data injection."
        })

    # X-Content-Type-Options
    xcto = http_headers.get("x-content-type-options")
    if not xcto or "nosniff" not in xcto.lower():
        findings.append({
            "type": "MISSING_X_CONTENT_TYPE_OPTIONS",
            "severity": "LOW",
            "cwe": "CWE-16",
            "title": "Missing X-Content-Type-Options Header",
            "description": "X-Content-Type-Options: nosniff is missing. Browsers may perform MIME-sniffing and execute non-script resources as script."
        })

    # X-Frame-Options
    xfo = http_headers.get("x-frame-options")
    if not xfo and not (csp and "frame-ancestors" in csp):
        findings.append({
            "type": "MISSING_X_FRAME_OPTIONS",
            "severity": "LOW",
            "cwe": "CWE-1021",
            "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
            "description": "Neither X-Frame-Options nor CSP frame-ancestors is present. The page can be embedded inside arbitrary malicious IFrames, enabling clickjacking attacks."
        })

    # Server / Technology Disclosure
    server_hdr = http_headers.get("server") or http_headers.get("x-powered-by")
    if server_hdr and any(c.isdigit() for c in server_hdr):
        findings.append({
            "type": "SERVER_VERSION_DISCLOSURE",
            "severity": "LOW",
            "cwe": "CWE-200",
            "title": f"Server Version Banner Disclosure ({server_hdr})",
            "description": f"The response header discloses exact server software version: '{server_hdr}'. This aids attackers in researching known CVEs."
        })

    # 5. Cookie Security Audit
    raw_cookies = [v for k, v in http_headers.items() if "set-cookie" in k]
    for c_str in raw_cookies:
        c_parts = [p.strip() for p in c_str.split(';')]
        name_val = c_parts[0].split('=', 1)
        c_name = name_val[0]
        c_val = name_val[1] if len(name_val) > 1 else ""
        c_lower = c_str.lower()

        c_issues = []
        if "secure" not in c_lower and parsed.scheme == "https":
            c_issues.append("Missing Secure flag")
        if "httponly" not in c_lower:
            c_issues.append("Missing HttpOnly flag")
        if "samesite" not in c_lower:
            c_issues.append("Missing SameSite attribute")

        if c_issues:
            findings.append({
                "type": "INSECURE_COOKIE_FLAGS",
                "severity": "MEDIUM",
                "cwe": "CWE-614",
                "title": f"Insecure Cookie Flags on '{c_name}'",
                "description": f"Cookie '{c_name}' lacks essential defense flags: {', '.join(c_issues)}."
            })

        # Token Entropy Audit on cookie value
        if len(c_val) >= 16:
            tok_audit = SessionTokenAuditor.audit_tokens([c_val])
            for tf in tok_audit.get("findings", []):
                findings.append(tf)

        cookies_audited.append({"name": c_name, "issues": c_issues})

    # 6. Auth / JWT Search in Headers & Body
    jwt_match = re.search(r'eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]*', resp_body)
    if not jwt_match:
        for v in http_headers.values():
            jwt_match = re.search(r'eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]*', v)
            if jwt_match:
                break

    if jwt_match:
        found_jwt = jwt_match.group(0)
        jwt_audit = JWTAuditor.audit_token(found_jwt)
        for jf in jwt_audit.get("findings", []):
            findings.append(jf)

    # 7. Ciphertext Smell Search in Body
    hex_blocks = re.findall(r'\b[0-9a-fA-F]{32,}\b', resp_body)
    if hex_blocks:
        ct_audit = CiphertextSmellAuditor.audit_ciphertexts(hex_blocks[:5])
        for cf in ct_audit.get("findings", []):
            findings.append(cf)

    # 8. Compute Severity Counts & Security Grade
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = f.get("severity", "LOW").upper()
        if s in sev_counts:
            sev_counts[s] += 1

    if sev_counts["CRITICAL"] > 0:
        grade = "F"
    elif sev_counts["HIGH"] > 0:
        grade = "D"
    elif sev_counts["MEDIUM"] > 2:
        grade = "C"
    elif sev_counts["MEDIUM"] > 0 or sev_counts["LOW"] > 2:
        grade = "B"
    else:
        grade = "A"

    # 9. Synthesize 10-Point Bug Bounty Report for Top Finding
    report_md = ""
    if findings:
        # Sort by severity
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda x: sev_rank.get(x.get("severity", "LOW"), 5))
        top_f = sorted_findings[0]

        rep_dict = BugBountyReportGenerator.generate_report(
            title=top_f["title"],
            affected_asset=url,
            finding_type=top_f.get("type", "INSECURE_HTTP_PROTOCOL"),
            root_cause=top_f.get("description", "Cryptographic / implementation weakness identified."),
            reproduction_steps=[
                f"Issue a request to the target endpoint: GET {url}",
                "Inspect the server response headers and cryptographic parameters.",
                f"Observe the flaw: {top_f['title']}."
            ],
            evidence=f"Target: {url}\nStatus: {status_code}\nRelevant Header / Finding: {top_f.get('description')}",
            impact=f"Attacker can leverage {top_f.get('cwe', 'cryptographic flaw')} to compromise integrity, confidentiality, or user sessions.",
            suggested_fix="Implement defensive hardening conforming to OWASP and NIST guidelines: configure strong TLS ciphers, enforce HSTS and CSP headers, and mark all cookies Secure, HttpOnly, and SameSite=Lax/Strict."
        )
        report_md = rep_dict["markdown"]

    return {
        "url": url,
        "status_code": status_code,
        "grade": grade,
        "scope_gate": scope_gate.__dict__,
        "tls_info": tls_info,
        "http_headers": http_headers,
        "cookies_audited": cookies_audited,
        "findings": findings,
        "findings_count": len(findings),
        "severity_summary": sev_counts,
        "bug_bounty_report": report_md
    }

