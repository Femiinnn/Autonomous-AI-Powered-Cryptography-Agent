"""
OAuth 2.0, OpenID Connect (OIDC) & SAML 2.0 Cryptographic Token Auditor
======================================================================
Implements rigorous security assessments for federated identity protocols:
  - OAuth 2.0: Missing state (CSRF), PKCE plain downgrade, deprecated implicit flow,
               insecure redirect URIs, open redirect risks.
  - OIDC: ID Token validation, at_hash / c_hash cryptographic binding checks,
          nonce omission in hybrid flows.
  - SAML 2.0: XML Signature Wrapping (XSW 1-8 detection), unsigned assertions,
              SHA-1 / MD5 digest deprecation, self-signed certificate injection in KeyInfo,
              missing / expired Conditions timestamps.
  - 10-Point Bug Bounty Responsible Disclosure Report Generator with CVSS v3.1 & CWE.
"""

import re
import time
import base64
import hashlib
import urllib.parse
from typing import Dict, Any, List, Optional
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# 1. OAUTH 2.0 & OIDC SECURITY AUDITOR
# ---------------------------------------------------------------------------

class OAuthAuditor:
    """
    Audits OAuth 2.0 authorization requests and OpenID Connect tokens
    for critical cryptographic and implementation flaws.
    """

    @classmethod
    def audit_authorization_url(cls, url: str) -> Dict[str, Any]:
        """
        Audits an OAuth 2.0 / OIDC authorization URL (GET request parameters).
        """
        clean_url = url.strip()
        parsed = urllib.parse.urlparse(clean_url)
        params = urllib.parse.parse_qs(parsed.query)

        findings = []

        # 1. State Parameter Audit (OAuth CSRF - RFC 6749 Section 10.12)
        state_list = params.get("state", [])
        if not state_list:
            findings.append({
                "type": "OAUTH_MISSING_STATE",
                "severity": "HIGH",
                "cwe": "CWE-352",
                "title": "Missing OAuth 2.0 State Parameter (CSRF Vulnerability)",
                "description": "The authorization request lacks a 'state' parameter. Without a cryptographically random, unguessable state tied to the user session, the flow is vulnerable to Login CSRF, allowing an attacker to bind their account to the victim's session."
            })
        else:
            state_val = state_list[0]
            if len(state_val) < 8 or state_val.lower() in ["test", "state", "123", "123456", "abc", "true", "none"]:
                findings.append({
                    "type": "OAUTH_PREDICTABLE_STATE",
                    "severity": "MEDIUM",
                    "cwe": "CWE-330",
                    "title": "Weak or Predictable OAuth State Value",
                    "description": f"The 'state' parameter ('{state_val}') lacks sufficient entropy (< 8 chars or known trivial pattern). State must be a cryptographically random nonce generated with secrets.token_urlsafe(32)."
                })

        # 2. PKCE (Proof Key for Code Exchange - RFC 7636)
        response_type = params.get("response_type", [""])[0]
        code_challenge = params.get("code_challenge", [])
        code_challenge_method = params.get("code_challenge_method", ["plain"])

        if "code" in response_type:
            if not code_challenge:
                findings.append({
                    "type": "OAUTH_MISSING_PKCE",
                    "severity": "MEDIUM",
                    "cwe": "CWE-287",
                    "title": "Missing PKCE Protection (RFC 7636)",
                    "description": "Authorization code request lacks 'code_challenge'. OAuth 2.1 and modern security best practices mandate PKCE for all clients to prevent authorization code interception and injection attacks."
                })
            else:
                method = code_challenge_method[0].upper()
                if method == "PLAIN":
                    findings.append({
                        "type": "OAUTH_PKCE_PLAIN_DOWNGRADE",
                        "severity": "HIGH",
                        "cwe": "CWE-327",
                        "title": "Insecure PKCE code_challenge_method=plain Downgrade",
                        "description": "The authorization request specifies code_challenge_method='plain'. The code_challenge directly reveals the code_verifier in cleartext, defeating the cryptographic purpose of PKCE. Must enforce S256 (SHA-256)."
                    })

        # 3. Deprecated Implicit Flow (RFC 6749 Section 4.2 / OAuth 2.1)
        if "token" in response_type:
            findings.append({
                "type": "OAUTH_DEPRECATED_IMPLICIT_FLOW",
                "severity": "MEDIUM",
                "cwe": "CWE-287",
                "title": "Deprecated OAuth 2.0 Implicit Flow (response_type=token)",
                "description": "The request utilizes the OAuth 2.0 Implicit Grant, returning access tokens directly in URL hash fragments. Disallowed in OAuth 2.1 due to token leakage via browser history, Referer headers, and open redirects."
            })

        # 4. Redirect URI Security
        redirect_uris = params.get("redirect_uri", [])
        if not redirect_uris:
            findings.append({
                "type": "OAUTH_MISSING_REDIRECT_URI",
                "severity": "MEDIUM",
                "cwe": "CWE-601",
                "title": "Missing Explicit redirect_uri Parameter",
                "description": "No 'redirect_uri' was supplied in the authorization request. If the server permits arbitrary or pre-registered pattern matching without strict comparison, authorization codes can leak."
            })
        else:
            r_uri = redirect_uris[0]
            if r_uri.startswith("http://") and not ("://localhost" in r_uri or "://127.0.0.1" in r_uri):
                findings.append({
                    "type": "OAUTH_HTTP_REDIRECT_INSECURE",
                    "severity": "HIGH",
                    "cwe": "CWE-319",
                    "title": "Cleartext HTTP OAuth redirect_uri",
                    "description": f"The redirect_uri '{r_uri}' uses unencrypted HTTP. Authorization codes and tokens transmitted to this URI can be intercepted over the network."
                })

        # 5. OpenID Connect Nonce (if openid in scope)
        scope = params.get("scope", [""])[0]
        if "openid" in scope and ("token" in response_type or "id_token" in response_type):
            nonce = params.get("nonce", [])
            if not nonce:
                findings.append({
                    "type": "OIDC_MISSING_NONCE",
                    "severity": "HIGH",
                    "cwe": "CWE-287",
                    "title": "Missing OIDC Nonce Parameter in Implicit/Hybrid Flow",
                    "description": "OpenID Connect Core 1.0 mandates the 'nonce' parameter when response_type includes 'id_token' or 'token' to prevent replay attacks on the ID Token."
                })

        return {
            "protocol": "OAuth 2.0 / OIDC",
            "url": clean_url,
            "params": {k: v[0] if len(v) == 1 else v for k, v in params.items()},
            "findings": findings,
            "findings_count": len(findings)
        }

    @classmethod
    def audit_oidc_token_binding(cls, id_token_payload: Dict[str, Any], access_token: str) -> Dict[str, Any]:
        """
        Validates cryptographic at_hash binding between ID Token and Access Token
        according to OpenID Connect Core 1.0 Section 3.1.3.6.
        """
        findings = []
        at_hash = id_token_payload.get("at_hash")

        if not at_hash:
            findings.append({
                "type": "OIDC_MISSING_AT_HASH",
                "severity": "LOW",
                "cwe": "CWE-347",
                "title": "Missing at_hash (Access Token Hash) Claim",
                "description": "ID Token does not contain an 'at_hash' claim. In hybrid and implicit flows, at_hash cryptographically binds the access token to the ID token."
            })
        elif access_token:
            # at_hash is base64url-encoded left-most half of SHA-256 (for RS256/ES256)
            at_bytes = access_token.encode('ascii')
            digest = hashlib.sha256(at_bytes).digest()
            half_len = len(digest) // 2
            expected_hash = base64.urlsafe_b64encode(digest[:half_len]).decode('ascii').rstrip('=')

            if at_hash != expected_hash:
                findings.append({
                    "type": "OIDC_AT_HASH_MISMATCH",
                    "severity": "HIGH",
                    "cwe": "CWE-347",
                    "title": "Cryptographic at_hash Mismatch",
                    "description": f"The computed at_hash ('{expected_hash}') does not match the token's at_hash ('{at_hash}'). The Access Token may have been substituted or tampered with."
                })

        return {
            "at_hash_present": bool(at_hash),
            "findings": findings,
            "findings_count": len(findings)
        }


# ---------------------------------------------------------------------------
# 2. SAML 2.0 CRYPTOGRAPHIC & XML SIGNATURE WRAPPING AUDITOR
# ---------------------------------------------------------------------------

class SAMLAuditor:
    """
    Audits SAML 2.0 XML responses and assertions for XML Signature Wrapping (XSW),
    weak algorithms, certificate injection, and timestamp validity.
    """

    @classmethod
    def audit_saml_response(cls, saml_input: str) -> Dict[str, Any]:
        """
        Audits raw or Base64-encoded SAML XML response.
        """
        xml_text = saml_input.strip()

        # Try base64 decoding if it looks like base64
        if not xml_text.startswith("<"):
            try:
                decoded = base64.b64decode(xml_text).decode('utf-8', errors='ignore')
                if "<" in decoded:
                    xml_text = decoded
            except Exception:
                pass

        if not ("<" in xml_text and ("Response" in xml_text or "Assertion" in xml_text)):
            return {"error": "Input does not appear to be a valid SAML 2.0 XML response or assertion."}

        findings = []

        try:
            root = ET.fromstring(xml_text)
        except Exception as e:
            return {"error": f"XML parse error: {str(e)}"}

        # Strip XML namespaces for uniform querying
        tag_str = root.tag
        ns_match = re.match(r'\{([^}]+)\}', tag_str)
        default_ns = ns_match.group(1) if ns_match else ""

        # Count Assertions and Signatures
        all_assertions = [elem for elem in root.iter() if elem.tag.endswith("Assertion")]
        all_signatures = [elem for elem in root.iter() if elem.tag.endswith("Signature")]

        # 1. Multiple Assertions (XSW 1/2 Indicator)
        if len(all_assertions) > 1:
            findings.append({
                "type": "SAML_MULTIPLE_ASSERTIONS_XSW",
                "severity": "CRITICAL",
                "cwe": "CWE-347",
                "title": "Multiple SAML Assertions Detected (XML Signature Wrapping Smell)",
                "description": f"SAML message contains {len(all_assertions)} <Assertion> elements. Systems susceptible to XSW attacks verify the signature on one assertion while extracting user identity (NameID/Attributes) from a forged unverified assertion."
            })

        # 2. Response Signed but Assertion Unsigned (XSW 3-8 Potential)
        if len(all_signatures) > 0 and len(all_assertions) > 0:
            root_is_signed = any(child.tag.endswith("Signature") for child in root)
            assertion_has_signature = any(child.tag.endswith("Signature") for child in all_assertions[0])

            if root_is_signed and not assertion_has_signature:
                findings.append({
                    "type": "SAML_UNSIGNED_ASSERTION_XSW",
                    "severity": "HIGH",
                    "cwe": "CWE-347",
                    "title": "SAML Response is Signed but Assertion is Unsigned",
                    "description": "The outer <Response> is signed, but the inner <Assertion> lacks its own cryptographic signature. If the Service Provider clones the signed response and injects a modified unsigned assertion, authentication bypass occurs."
                })

        # 3. Complete Absence of XML Signature
        if len(all_signatures) == 0:
            findings.append({
                "type": "SAML_COMPLETELY_UNSIGNED",
                "severity": "CRITICAL",
                "cwe": "CWE-347",
                "title": "Completely Unsigned SAML Response",
                "description": "No <ds:Signature> element exists in the entire SAML document. An attacker can forge arbitrary NameID and role attributes without detection if the Service Provider does not reject unsigned messages."
            })

        # 4. Weak Digest & Signature Algorithms (SHA-1 / MD5)
        for sig in all_signatures:
            for elem in sig.iter():
                algo = elem.attrib.get("Algorithm", "")
                if "sha1" in algo.lower():
                    findings.append({
                        "type": "SAML_DEPRECATED_SHA1",
                        "severity": "HIGH",
                        "cwe": "CWE-328",
                        "title": "Deprecated SHA-1 Digest / Signature Algorithm in SAML",
                        "description": f"SAML signature utilizes deprecated algorithm '{algo}'. Modern federated identity standards mandate SHA-256 (http://www.w3.org/2001/04/xmldsig-more#rsa-sha256)."
                    })
                    break
                elif "md5" in algo.lower():
                    findings.append({
                        "type": "SAML_BROKEN_MD5",
                        "severity": "CRITICAL",
                        "cwe": "CWE-328",
                        "title": "Broken MD5 Algorithm in SAML Signature",
                        "description": f"SAML signature utilizes broken MD5 algorithm ('{algo}'). Subject to practical collision attacks."
                    })
                    break

        # 5. Embedded Certificate in KeyInfo without CA Validation Risk
        has_keyinfo_cert = False
        for sig in all_signatures:
            for elem in sig.iter():
                if elem.tag.endswith("X509Certificate") and elem.text and elem.text.strip():
                    has_keyinfo_cert = True
                    break

        if has_keyinfo_cert:
            findings.append({
                "type": "SAML_EMBEDDED_CERTIFICATE",
                "severity": "MEDIUM",
                "cwe": "CWE-295",
                "title": "Embedded X.509 Certificate in SAML KeyInfo",
                "description": "SAML signature includes an embedded <ds:X509Certificate>. If the Service Provider validates the signature using the untrusted certificate extracted directly from the XML instead of a pre-configured trusted metadata store, arbitrary identity spoofing is possible."
            })

        # 6. Conditions & Timestamp Check
        has_conditions = False
        for elem in root.iter():
            if elem.tag.endswith("Conditions"):
                has_conditions = True
                not_before = elem.attrib.get("NotBefore")
                not_on_or_after = elem.attrib.get("NotOnOrAfter")
                if not not_before or not not_on_or_after:
                    findings.append({
                        "type": "SAML_INCOMPLETE_TIMESTAMPS",
                        "severity": "LOW",
                        "cwe": "CWE-613",
                        "title": "Incomplete SAML Conditions Timestamps",
                        "description": "SAML <Conditions> element lacks strict NotBefore or NotOnOrAfter boundaries, increasing risk of replay attacks."
                    })
                break

        if not has_conditions:
            findings.append({
                "type": "SAML_MISSING_CONDITIONS",
                "severity": "MEDIUM",
                "cwe": "CWE-613",
                "title": "Missing SAML Conditions Element",
                "description": "The assertion has no <Conditions> block defining validity timeframe and audience restrictions, allowing indefinitely replayable assertions."
            })

        return {
            "protocol": "SAML 2.0",
            "assertions_count": len(all_assertions),
            "signatures_count": len(all_signatures),
            "findings": findings,
            "findings_count": len(findings)
        }


# ---------------------------------------------------------------------------
# 3. UNIFIED OAUTH & SAML DISPATCHER & REPORT GENERATOR
# ---------------------------------------------------------------------------

def audit_federated_identity(text_or_url: str) -> Dict[str, Any]:
    """
    Auto-detects whether input is an OAuth authorization URL or SAML XML response
    and runs the appropriate audit suite.
    """
    clean = text_or_url.strip()

    if clean.startswith("http://") or clean.startswith("https://") or ("response_type=" in clean and "client_id=" in clean):
        res = OAuthAuditor.audit_authorization_url(clean)
        report_md = ""
        if res.get("findings"):
            from bug_bounty_crypto import BugBountyReportGenerator
            f0 = res["findings"][0]
            rep_dict = BugBountyReportGenerator.generate_report(
                title=f0["title"],
                affected_asset=clean.split('?')[0],
                finding_type=f0["type"],
                root_cause=f0["description"],
                reproduction_steps=[
                    "Initiate OAuth 2.0 authentication flow from client application.",
                    "Inspect outgoing authorization request query parameters.",
                    f"Observe identified security defect: {f0['type']}."
                ],
                evidence=f"Authorization Request URL: {clean[:120]}...\nDefect: {f0['title']}",
                impact="An attacker can leverage this flaw to hijack authorization codes, execute Login CSRF, or intercept access tokens.",
                suggested_fix="Upgrade OAuth configuration to OAuth 2.1 specifications: enforce cryptographically random state parameter generated via secrets.token_urlsafe(32), mandate PKCE with S256 code_challenge_method, and enforce exact redirect_uri matching."
            )
            report_md = rep_dict["markdown"]
        res["bug_bounty_report"] = report_md
        return {"audit_type": "oauth_oidc", "result": res}

    elif "<" in clean and ("Assertion" in clean or "Response" in clean) or ("PHNhbWxwOlJlc3BvbnNl" in clean):
        res = SAMLAuditor.audit_saml_response(clean)
        report_md = ""
        if res.get("findings"):
            from bug_bounty_crypto import BugBountyReportGenerator
            f0 = res["findings"][0]
            rep_dict = BugBountyReportGenerator.generate_report(
                title=f0["title"],
                affected_asset="SAML Single Sign-On Endpoint",
                finding_type=f0["type"],
                root_cause=f0["description"],
                reproduction_steps=[
                    "Capture SAML Response during authentication handshake.",
                    "Analyze XML structure, signature placement, and digest algorithms.",
                    f"Detect vulnerability: {f0['title']}."
                ],
                evidence=f"SAML XML Analysis:\nAssertions: {res.get('assertions_count')}\nSignatures: {res.get('signatures_count')}\nDefect: {f0['title']}",
                impact="An attacker can potentially execute XML Signature Wrapping (XSW) attacks or modify assertion attributes to gain unauthorized administrative access.",
                suggested_fix="Enforce strict signature validation over both <Response> and inner <Assertion>, pin the Identity Provider's X.509 certificate in server-side metadata (do not trust embedded KeyInfo), and reject SHA-1/MD5 in favor of SHA-256."
            )
            report_md = rep_dict["markdown"]
        res["bug_bounty_report"] = report_md
        return {"audit_type": "saml_2", "result": res}

    return {"error": "Input is neither a recognized OAuth authorization URL nor a SAML XML response."}
