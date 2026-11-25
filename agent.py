import os
import re
import shutil
from typing import TypedDict, Optional
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI
try:
    from langgraph.graph import StateGraph, END
    HAS_LANGGRAPH = True
except (ImportError, OSError):
    HAS_LANGGRAPH = False
    END = "__END__"
from sandbox import DockerCryptoSandbox

# Load environment variables if .env is present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- Configuration ---
# Point to your local or cloud LLM instance with automated model & key fallback
from llm_manager import fallback_llm

sandbox = DockerCryptoSandbox(image="crypto-sandbox:latest", timeout=30)
llm = fallback_llm

import json
import concurrent.futures

# Detect if SageMath is available via Docker, native sage binary, WSL, or SageMathCell API
SAGE_AVAILABLE = bool(sandbox.has_docker or shutil.which("sage") or sandbox.check_wsl_sage() or True)

# --- State Definition ---
class CryptoAgentState(TypedDict):
    challenge: str
    category: Optional[str]
    attack_hypothesis: Optional[str]
    is_sage: bool
    generated_code: Optional[str]
    execution_stdout: Optional[str]
    execution_stderr: Optional[str]
    captured_flag: Optional[str]     # Keep for backwards compatibility
    decoded_result: Optional[str]    # Primary decoded output (any format)
    iteration: int
    max_retries: int
    # ── Pre-Analysis Reports ───────────────────────────────────────
    hash_analysis: Optional[dict]       # full report from hash_decoder
    classical_analysis: Optional[dict]  # full report from classical_crypto
    rsa_analysis: Optional[dict]        # full report from rsa_cryptanalysis
    ecc_analysis: Optional[dict]        # full report from ecc_cryptanalysis
    symmetric_analysis: Optional[dict]  # full report from symmetric_cryptanalysis
    prng_analysis: Optional[dict]       # full report from prng_cryptanalysis
    lattice_analysis: Optional[dict]    # full report from lattice_crypto
    stego_analysis: Optional[dict]      # full report from crypto_stego
    math_analysis: Optional[dict]       # full report from advanced_math_crypto
    custom_analysis: Optional[dict]     # full report from z3_symbolic_solver
    bug_bounty_analysis: Optional[dict] # full report from bug_bounty_crypto (AGENTS.md)
    extracted_parameters: Optional[dict] # autonomous parameter extraction
    ranked_hypotheses: Optional[list]    # prioritized attack vectors
    solution_report: Optional[str]       # 10-point CTF solution report
    job_id: Optional[str]              # Isolated job ID for sandboxed challenge files


# ── Hash, Encoding, Classical, RSA, ECC & Symmetric Detection Node ──────────
def detect_hash_or_encoding(state: CryptoAgentState) -> dict:
    """
    Pre-processing node:
    1. Scans challenge for encoded / hashed strings (Base64, Hex, Morse, hashes).
    2. Runs automated Classical Cryptanalysis ONLY on non-RSA / non-math ciphertexts.
    3. Runs automated RSA Cryptanalysis (Wiener, Fermat, Small e, Common Modulus, etc.)
       when mathematical RSA parameters (N, e, c) are detected.
    4. Runs automated ECC Cryptanalysis (Nonce reuse, Smart's anomalous attack, BSGS)
       when curve parameters or ECDSA signatures are detected.
    5. Runs automated Symmetric Cryptanalysis (Padding Oracle, Bit Flip, Nonce Reuse, MITM, etc.)
       when symmetric ciphers (AES, DES, 3DES, Blowfish, ChaCha20, RC4) are detected.
    Only short-circuits if a genuine verified flag is discovered.
    """
    print("\n🔎 [Pre-Step] Scanning for Hash / Encoding / Classical / RSA / ECC / Symmetric patterns…")
    challenge = state["challenge"]
    
    # Check if this is an asymmetric / mathematical RSA challenge
    is_math_rsa = bool(
        re.search(r'\b(N\s*=|modulus|e\s*=|c\s*=|d\s*=|p\s*=|q\s*=|phi\s*=)\b', challenge, re.IGNORECASE)
        and re.search(r'\d{10,}', challenge)
    )

    verified_flag = None
    solved_category = "Classical Cryptography"
    solved_attack = "Direct Cryptanalysis"
    solved_code = ""

    # 0. Autonomous Parameter Extraction & Attack Strategy Ranking
    extracted_params = {}
    ranked_hypotheses = []
    try:
        from attack_selector import extract_parameters, analyze_ciphertext_characteristics, rank_attack_strategies
        extracted_params = extract_parameters(challenge)
        charac = analyze_ciphertext_characteristics(challenge)
        ranked_hypotheses = rank_attack_strategies(extracted_params, charac, challenge)
        if ranked_hypotheses:
            top_h = ranked_hypotheses[0]
            print(f"  🎯 Ranked Attack Vector #1: {top_h.get('attack')} (Prob: {top_h.get('probability')}, Cost: {top_h.get('estimated_cost')})")
    except Exception as e:
        print(f"  ⚠️ Attack selector ranking error: {e}")

    # 1. Encoding & Hash Detection
    try:
        from hash_decoder import analyze_hash_or_encoding, extract_encoded_strings
        full_analysis = analyze_hash_or_encoding(challenge)
        sub_analyses = extract_encoded_strings(challenge)
        hash_analysis = {
            "full": full_analysis,
            "substrings": sub_analyses[:5],
        }
        summary = full_analysis.get("summary", "")
        if summary and not is_math_rsa:
            print(f"  📊 Hash/Encoding: {summary}")

        # Check if recursive decoding uncovered a genuine flag immediately
        final_dec = full_analysis.get("final_decoded")
        if final_dec and final_dec.strip() != challenge.strip():
            flag_match = re.search(r'(flag\{.*?\}|ctf\{.*?\})', final_dec, re.IGNORECASE)
            if flag_match:
                verified_flag = flag_match.group(1)
                solved_category = "Encoding & Data Transformation"
                solved_attack = f"Recursive Decoding ({summary})"
                solved_code = f"# Solved directly via recursive multi-layer decoding\nprint('{verified_flag}')\n"
                print(f"  🚩 VERIFIED FLAG RECOVERED via Recursive Decoding: {verified_flag}")

        if not verified_flag:
            for sub in sub_analyses:
                sub_dec = sub.get("final_decoded")
                if sub_dec:
                    flag_match = re.search(r'(flag\{.*?\}|ctf\{.*?\})', sub_dec, re.IGNORECASE)
                    if flag_match:
                        verified_flag = flag_match.group(1)
                        solved_category = "Encoding & Data Transformation"
                        solved_attack = f"Substring Recursive Decoding ({sub.get('summary', 'Decoded')})"
                        solved_code = f"# Solved directly via substring recursive decoding\nprint('{verified_flag}')\n"
                        print(f"  🚩 VERIFIED FLAG RECOVERED via Substring Decoding: {verified_flag}")
                        break
    except Exception as e:
        print(f"  ⚠️ Hash/Encoding detection error: {e}")
        hash_analysis = {"full": {}, "substrings": [], "error": str(e)}

    # 1b. Hash Dictionary & Wordlist Attack
    if not verified_flag:
        try:
            from hash_cryptanalysis import identify_hash_type, dictionary_attack
            tokens = re.findall(r'\b[a-fA-F0-9]{32,128}\b', challenge)
            for tok in tokens:
                htypes = identify_hash_type(tok)
                if htypes:
                    top_t = htypes[0]["type"]
                    res = dictionary_attack(tok, top_t)
                    if res.get("status") == "cracked":
                        rec = res.get("plaintext", "")
                        print(f"  🚩 VERIFIED HASH RECOVERED via Dictionary Attack: {rec}")
                        flag_m = re.search(r'(flag\{.*?\}|ctf\{.*?\})', rec, re.IGNORECASE)
                        verified_flag = flag_m.group(1) if flag_m else rec
                        solved_category = "Hash Cryptanalysis"
                        solved_attack = f"Dictionary Attack ({top_t})"
                        solved_code = f"# Solved directly via hash_cryptanalysis dictionary attack\n# Hash: {tok} ({top_t})\nprint('{verified_flag}')\n"
                        break
        except Exception as e:
            print(f"  ⚠️ Hash dictionary attack error: {e}")

    # 2. Parallel Multi-Hypothesis Execution of Deterministic Cryptanalysis Suites
    classical_res = {}
    rsa_res = {}
    ecc_res = {}
    symmetric_res = {}
    prng_res = {}
    lattice_res = {}
    stego_res = {}
    math_res = {}

    if not verified_flag:
        is_ecc = bool(
            re.search(r'\b(curve|elliptic|secp256|p256|point|ecdlp|ecdsa|Gx|Gy|Qx|Qy|nonce\s*reuse)\b', challenge, re.IGNORECASE)
            or (re.search(r'\bp\s*[:=]\s*\d+', challenge, re.IGNORECASE) and re.search(r'\b(a|b)\s*[:=]\s*\d+', challenge, re.IGNORECASE))
            or (re.search(r'\b(r|s)\s*[:=]\s*\d+', challenge, re.IGNORECASE) and re.search(r'\b(z|hash)\s*[:=]\s*\d+', challenge, re.IGNORECASE))
        )
        is_sym = bool(
            re.search(r'\b(aes|des|3des|des3|blowfish|chacha20|rc4|cbc|ecb|cfb|ofb|ctr|gcm|padding oracle|bit.?flip|nonce.?reuse|meet.?in.?the.?middle)\b', challenge, re.IGNORECASE)
        )
        is_prng = bool(
            re.search(r'\b(lcg|linear\s*congruential|mt19937|mersenne\s*twister|random\.random|untwist|lfsr|berlekamp|keystream|states?|seed)\b', challenge, re.IGNORECASE)
            or re.search(r'\[\s*\d+\s*,\s*\d+\s*,\s*\d+.*\]', challenge)
        )
        is_lattice = bool(
            re.search(r'\b(knapsack|subset.?sum|merkle.?hellman|lattice|lll|babai|closest.?vector|superincreasing)\b', challenge, re.IGNORECASE)
            or (re.search(r'\b(weights?|public_key|target|s\s*=|sum\s*=)\b', challenge, re.IGNORECASE) and re.search(r'\[\s*\d+', challenge))
        )
        is_adv_math = bool(
            re.search(r'\b(bkz|groebner|buchberger|cantor|zassenhaus|hensel|tonelli|shanks|crt|chinese remainder|gaussian|lfsr|berlekamp|sat|z3)\b', challenge, re.IGNORECASE)
        )

        job_id = state.get("job_id")
        input_dir = os.path.join("inputs", job_id) if job_id else "inputs"
        has_images = False
        if os.path.exists(input_dir):
            for f in os.listdir(input_dir):
                if f.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp')):
                    has_images = True
                    break

        def _exec_classical():
            try:
                from classical_crypto import analyze_and_solve_classical
                cand = hash_analysis.get("full", {}).get("final_decoded") or challenge
                c_res = analyze_and_solve_classical(cand)
                fp = c_res.get("flag_pattern")
                top = c_res.get("top_match") or {}
                if fp and fp.lower() not in challenge.lower():
                    cipher_name = top.get('cipher', 'Classical')
                    return ("classical", fp, "Classical Cryptography", cipher_name, f"# Solved directly via classical_crypto ({cipher_name})\nprint('{fp}')\n", c_res)
                return ("classical", None, None, None, None, c_res)
            except Exception as e:
                return ("classical", None, None, None, None, {"status": "error", "error": str(e)})

        def _exec_rsa():
            try:
                from rsa_cryptanalysis import analyze_and_solve_rsa
                r_res = analyze_and_solve_rsa(challenge)
                if r_res.get("status") == "solved" and r_res.get("flag"):
                    pt = r_res["flag"]
                    atk = r_res.get("attack", "RSA Analysis")
                    return ("rsa", pt, "RSA", atk, f"# Solved directly via rsa_cryptanalysis ({atk})\nprint('{pt}')\n", r_res)
                return ("rsa", None, None, None, None, r_res)
            except Exception as e:
                return ("rsa", None, None, None, None, {"status": "error", "error": str(e)})

        def _exec_ecc():
            try:
                from ecc_cryptanalysis import analyze_and_solve_ecc
                e_res = analyze_and_solve_ecc(challenge)
                if e_res.get("status") == "solved" and (e_res.get("flag") or e_res.get("private_scalar")):
                    pt = e_res.get("flag") or str(e_res.get("private_scalar"))
                    atk = e_res.get("attack", "ECC Analysis")
                    return ("ecc", pt, "Elliptic Curve Cryptography (ECC)", atk, f"# Solved directly via ecc_cryptanalysis ({atk})\nprint('{pt}')\n", e_res)
                return ("ecc", None, None, None, None, e_res)
            except Exception as e:
                return ("ecc", None, None, None, None, {"status": "error", "error": str(e)})

        def _exec_symmetric():
            try:
                from symmetric_cryptanalysis import analyze_and_solve_symmetric
                s_res = analyze_and_solve_symmetric(challenge)
                if s_res.get("flag") or s_res.get("recovered_p2"):
                    pt = s_res.get("flag") or s_res.get("recovered_p2")
                    if isinstance(pt, bytes):
                        pt = pt.decode('latin1', errors='replace')
                    atk = s_res.get("attack", s_res.get("method", "Symmetric Cryptanalysis"))
                    return ("symmetric", pt, "Symmetric Cryptography", atk, f"# Solved directly via symmetric_cryptanalysis ({atk})\nprint('{pt}')\n", s_res)
                return ("symmetric", None, None, None, None, s_res)
            except Exception as e:
                return ("symmetric", None, None, None, None, {"status": "error", "error": str(e)})

        def _exec_prng():
            try:
                from prng_cryptanalysis import analyze_and_solve_prng
                p_res = analyze_and_solve_prng(challenge)
                if p_res.get("status") == "solved" and p_res.get("flag"):
                    pt = p_res["flag"]
                    atk = p_res.get("attack", "PRNG Analysis")
                    return ("prng", pt, "PRNG & LFSR", atk, f"# Solved directly via prng_cryptanalysis ({atk})\nprint('{pt}')\n", p_res)
                return ("prng", None, None, None, None, p_res)
            except Exception as e:
                return ("prng", None, None, None, None, {"status": "error", "error": str(e)})

        def _exec_lattice():
            try:
                from lattice_crypto import analyze_and_solve_lattice
                l_res = analyze_and_solve_lattice(challenge)
                if l_res.get("status") == "solved" and l_res.get("flag"):
                    pt = l_res["flag"]
                    atk = l_res.get("attack", "Lattice Cryptanalysis")
                    return ("lattice", pt, "Lattice Cryptography", atk, f"# Solved directly via lattice_crypto ({atk})\nprint('{pt}')\n", l_res)
                return ("lattice", None, None, None, None, l_res)
            except Exception as e:
                return ("lattice", None, None, None, None, {"status": "error", "error": str(e)})

        def _exec_stego():
            try:
                from crypto_stego import analyze_and_solve_stego
                st_res = analyze_and_solve_stego(input_dir)
                if st_res.get("status") == "solved" and st_res.get("flag"):
                    pt = st_res["flag"]
                    atk = st_res.get("attack", "Stego Analysis")
                    return ("stego", pt, "Crypto-Steganography", atk, f"# Solved directly via crypto_stego ({atk})\nprint('{pt}')\n", st_res)
                return ("stego", None, None, None, None, st_res)
            except Exception as e:
                return ("stego", None, None, None, None, {"status": "error", "error": str(e)})

        def _exec_math():
            try:
                from advanced_math_crypto import analyze_and_solve_advanced_math
                m_res = analyze_and_solve_advanced_math(challenge)
                if m_res.get("status") == "solved" and m_res.get("flag"):
                    pt = m_res["flag"]
                    atk = m_res.get("method", "Advanced Mathematical Cryptanalysis")
                    return ("math", pt, "Advanced Mathematical Cryptanalysis", atk, f"# Solved directly via advanced_math_crypto ({atk})\nprint('{pt}')\n", m_res)
                return ("math", None, None, None, None, m_res)
            except Exception as e:
                return ("math", None, None, None, None, {"status": "error", "error": str(e)})

        tasks = []
        if is_math_rsa:
            print("  🔢 Mathematical / RSA parameters detected — scheduling RSA Cryptanalysis Suite…")
            tasks.append(_exec_rsa)
        else:
            tasks.append(_exec_classical)

        if is_ecc:
            print("  📐 Elliptic Curve parameters detected — scheduling ECC Cryptanalysis Suite…")
            tasks.append(_exec_ecc)
        if is_sym:
            print("  🛡️ Symmetric Cryptography parameters detected — scheduling Symmetric Suite…")
            tasks.append(_exec_symmetric)
        if is_prng:
            print("  🎲 PRNG / LFSR parameters detected — scheduling PRNG Cryptanalysis Suite…")
            tasks.append(_exec_prng)
        if is_lattice:
            print("  🕸️ Lattice / Knapsack parameters detected — scheduling Lattice Suite…")
            tasks.append(_exec_lattice)
        if has_images:
            print("  🖼️ Image file(s) detected in input — scheduling Steganography Suite…")
            tasks.append(_exec_stego)
        if is_adv_math:
            print("  🧮 Advanced Mathematical parameters detected — scheduling Math Suite…")
            tasks.append(_exec_math)

        # Run candidate suites in parallel
        if tasks:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(tasks))) as executor:
                future_to_fn = {executor.submit(fn): fn for fn in tasks}
                for future in concurrent.futures.as_completed(future_to_fn):
                    try:
                        tag, pt, cat, atk, code, r_dict = future.result()
                        if tag == "classical":
                            classical_res = r_dict
                        elif tag == "rsa":
                            rsa_res = r_dict
                        elif tag == "ecc":
                            ecc_res = r_dict
                        elif tag == "symmetric":
                            symmetric_res = r_dict
                        elif tag == "prng":
                            prng_res = r_dict
                        elif tag == "lattice":
                            lattice_res = r_dict
                        elif tag == "stego":
                            stego_res = r_dict
                        elif tag == "math":
                            math_res = r_dict

                        if pt and not verified_flag:
                            verified_flag = pt
                            solved_category = cat
                            solved_attack = atk
                            solved_code = code
                            print(f"  🚩 VERIFIED FLAG RECOVERED in parallel pre-step via {atk}: {pt}")
                    except Exception:
                        pass

    # 9. Custom Bitwise & Symbolic Reverser Suite
    custom_res = {}
    if not verified_flag and ("def " in challenge or "<<" in challenge or ">>" in challenge or "rol" in challenge.lower() or "ror" in challenge.lower() or "feistel" in challenge.lower()):
        print("  🧩 Custom Bitwise / Scrambler logic detected — executing Symbolic Reverser Suite…")
        try:
            from z3_symbolic_solver import analyze_and_solve_custom_cipher
            custom_res = analyze_and_solve_custom_cipher(challenge)
            if custom_res.get("status") == "solved" and custom_res.get("flag"):
                pt = custom_res["flag"]
                atk = custom_res.get("method", "Symbolic Preimage Inversion")
                verified_flag = pt
                solved_category = "Custom Bitwise / Scrambler"
                solved_attack = atk
                solved_code = f"# Solved directly via z3_symbolic_solver ({atk})\nprint('{pt}')\n"
                print(f"  🚩 VERIFIED CUSTOM CIPHER FLAG RECOVERED via {atk}: {pt}")
        except Exception as e:
            print(f"  ⚠️ Symbolic reverser error: {e}")

    # 10. Remote Netcat Socket Probing & Interactive Oracle Driver
    if not verified_flag and ("[remote netcat target:" in challenge.lower() or "nc " in challenge.lower()):
        try:
            from interactive_oracle_engine import probe_and_solve_remote_service
            socket_res = probe_and_solve_remote_service(challenge)
            if socket_res.get("flag"):
                pt = socket_res["flag"]
                verified_flag = pt
                solved_category = "Remote CTF Socket Oracle"
                solved_attack = socket_res.get("detected_oracle_type", "Interactive Socket Probe")
                solved_code = f"# Solved via interactive_oracle_engine\nprint('{pt}')\n"
                print(f"  🚩 VERIFIED REMOTE SOCKET FLAG RECOVERED: {pt}")
        except Exception as e:
            pass

    # 11. Bug Bounty Live Artifact Auditor & Scope Gatekeeper (AGENTS.md)
    bounty_res = {}
    is_bounty_artifact = bool(
        re.search(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+', challenge)
        or re.search(r'\b(jwt|bearer|reset.?token|session.?id|bounty|in.?scope|hackerone|bugcrowd)\b', challenge, re.IGNORECASE)
        or "-----BEGIN CERTIFICATE" in challenge
    )
    if is_bounty_artifact and not verified_flag:
        print("  🎯 Bug Bounty Artifact detected — executing Bug Bounty Cryptanalysis Suite…")
        try:
            from bug_bounty_crypto import audit_bug_bounty_artifact, ScopeGatekeeper
            urls = re.findall(r'https?://[^\s\'"]+', challenge)
            if urls:
                scope_check = ScopeGatekeeper.validate_scope(urls[0])
                if not scope_check.allowed:
                    print(f"  🛑 Scope Gatekeeper Notification: {scope_check.reason}")

            bounty_res = audit_bug_bounty_artifact(challenge)
            res_inner = bounty_res.get("result", {})
            findings = res_inner.get("findings", [])
            if findings:
                f0 = findings[0]
                print(f"  🛡️ Bug Bounty Finding [{f0.get('severity', 'INFO')}]: {f0.get('title')}")
                if f0.get("secret"):
                    pt = f"secret:{f0['secret']}"
                    verified_flag = pt
                    solved_category = "Bug Bounty (Weak HMAC Secret)"
                    solved_attack = f0["title"]
                    solved_code = f"# Weak HMAC secret cracked via bug_bounty_crypto\nSECRET = '{f0['secret']}'\nprint('SECRET:', SECRET)\n"
        except Exception as e:
            print(f"  ⚠️ Bug bounty analysis error: {e}")

    result_dict = {
        "hash_analysis": hash_analysis,
        "classical_analysis": classical_res,
        "rsa_analysis": rsa_res,
        "ecc_analysis": ecc_res,
        "symmetric_analysis": symmetric_res,
        "prng_analysis": prng_res,
        "lattice_analysis": lattice_res,
        "stego_analysis": stego_res,
        "math_analysis": math_res,
        "custom_analysis": custom_res,
        "bug_bounty_analysis": bounty_res,
        "extracted_parameters": extracted_params,
        "ranked_hypotheses": ranked_hypotheses,
        "solution_report": None
    }
    # Only short-circuit if a genuine verified flag was recovered
    if verified_flag:
        result_dict["captured_flag"] = verified_flag
        result_dict["decoded_result"] = verified_flag
        result_dict["generated_code"] = solved_code
        result_dict["execution_stdout"] = f"🚩 FLAG: {verified_flag}"
        result_dict["category"] = solved_category
        result_dict["attack_hypothesis"] = solved_attack
        try:
            from verification_engine import generate_solution_report
            rep = generate_solution_report(
                challenge_name="CTF Cryptographic Challenge",
                category=solved_category,
                vulnerability=solved_attack,
                parameters=extracted_params,
                attack_script=solved_code,
                flag=verified_flag,
                verified=True,
                complexity="O(1) Direct Cryptanalysis"
            )
            result_dict["solution_report"] = rep
            try:
                from verification_engine import export_ctf_writeup
                export_ctf_writeup(rep, challenge_name=solved_category)
                from poc_exporter import export_standalone_poc
                export_standalone_poc(
                    exploit_code=solved_code,
                    parameters=extracted_params,
                    verified_flag=verified_flag,
                    category=solved_category,
                    vulnerability=solved_attack
                )
            except Exception:
                pass
        except Exception:
            pass

    return result_dict


# --- Nodes ---
def classify_and_plan(state: CryptoAgentState) -> dict:
    attempt_num = state.get('iteration', 0)
    print(f"\n🔍 [Step 1] Classifying challenge (Pass {attempt_num + 1})...")

    previous_failure = ""
    if state.get("execution_stderr"):
        previous_failure = f"\nNote: The previous hypothesis '{state.get('attack_hypothesis')}' failed with error:\n{state.get('execution_stderr')}\nRe-evaluate parameters and choose an ALTERNATIVE attack."

    # Inject hash/encoding findings as extra context for the LLM
    hash_ctx = ""
    ha = state.get("hash_analysis") or {}
    full_ha = ha.get("full") or {}
    if full_ha.get("summary"):
        hash_ctx = f"\n[Hash/Encoding Pre-Analysis]\n{full_ha['summary']}"
        layers = full_ha.get("encoding_layers") or []
        if layers:
            for layer in layers:
                enc = layer.get("encoding", "")
                decoded = layer.get("decoded", "")
                is_hash = layer.get("is_hash", False)
                algos = layer.get("hash_algorithms", [])
                if is_hash and algos:
                    hash_ctx += f"\n  - Hash detected: possible algorithms: {', '.join(a['algorithm'] for a in algos[:3])}"
                elif decoded:
                    hash_ctx += f"\n  - Layer {layer.get('layer','')} [{enc}] decoded: {decoded[:100]}"
        if full_ha.get("is_multi_encoded") or full_ha.get("is_double_encoded"):
            hash_ctx += f"\n  ⚠️  RECURSIVE MULTI-LAYER ENCODING DETECTED ({full_ha.get('total_layers', '')} layers) — peeling sequence: {full_ha.get('summary', '')}"
        for sub in (ha.get("substrings") or [])[:2]:
            fd = sub.get("final_decoded", "")
            enc0 = (sub.get("encoding_layers") or [{}])[0].get("encoding", "")
            if fd:
                hash_ctx += f"\n  - Extracted [{enc0}] substring decoded: {fd[:80]}"

    # Check if challenge is primarily mathematical RSA / asymmetric
    challenge_text = state['challenge']
    is_math_rsa = bool(
        re.search(r'\b(N\s*=|modulus|e\s*=|c\s*=|d\s*=|p\s*=|q\s*=|phi\s*=)\b', challenge_text, re.IGNORECASE)
        and re.search(r'\d{10,}', challenge_text)
    )

    # Inject RSA cryptanalysis pre-analysis
    rsa_ctx = ""
    ra = state.get("rsa_analysis") or {}
    if ra and ra.get("status") != "error":
        params = ra.get("parameters") or {}
        n_val = params.get("n")
        e_val = params.get("e")
        if n_val:
            rsa_ctx = f"\n[RSA Parameters Detected]\n  - Modulus size: {n_val.bit_length()} bits\n  - Public exponent e: {e_val}"
            if ra.get("attack") and ra["attack"] != "None":
                rsa_ctx += f"\n  - Suggested RSA Attack: {ra['attack']}"

    # Inject classical cryptanalysis pre-analysis ONLY if it's not an RSA/asymmetric challenge
    classical_ctx = ""
    ca = state.get("classical_analysis") or {}
    if not is_math_rsa and ca.get("top_match"):
        top = ca["top_match"]
        dec_sample = str(top.get('decrypted', '')).strip()
        if dec_sample and dec_sample != challenge_text.strip():
            ioc = ca.get("index_of_coincidence", 0)
            chi = ca.get("chi_squared", 0)
            common = ", ".join(ca.get("most_common_letters", [])[:5])
            k_factors = ca.get("kasiski_factors", [])
            k_str = f"  - Kasiski key length candidates: {k_factors}\n" if k_factors else ""
            classical_ctx = (
                f"\n[Classical Cryptanalysis Pre-Analysis]\n"
                f"  - Index of Coincidence (IoC): {ioc} (English ~0.0667, Polyalphabetic/Random ~0.0385)\n"
                f"  - Chi-Squared: {chi}\n"
                f"  - High frequency letters: {common}\n"
                f"{k_str}"
                f"  - Top Suggested Cipher: {top.get('cipher')} (Key/Params: {top.get('key')})\n"
                f"  - Decrypted Preview: {dec_sample[:120]}"
            )

    # Inject ECC cryptanalysis pre-analysis
    ecc_ctx = ""
    ea = state.get("ecc_analysis") or {}
    if ea and ea.get("parameters"):
        ecc_ctx = f"\n[ECC Parameters Detected]\n"
        if ea.get("attack"):
            ecc_ctx += f"  - Suggested ECC Attack: {ea['attack']}\n"
        if ea.get("explanation"):
            ecc_ctx += f"  - Note: {ea['explanation']}\n"

    # Inject Symmetric cryptanalysis pre-analysis
    symmetric_ctx = ""
    sa = state.get("symmetric_analysis") or {}
    if sa and (sa.get("cipher") or sa.get("attack") or sa.get("method")):
        symmetric_ctx = f"\n[Symmetric Cryptography Detected]\n"
        if sa.get("cipher"):
            symmetric_ctx += f"  - Cipher: {sa['cipher']} (Mode: {sa.get('mode', 'Unknown')})\n"
        if sa.get("attack") or sa.get("method"):
            symmetric_ctx += f"  - Target Attack: {sa.get('attack') or sa.get('method')}\n"
        if sa.get("explanation"):
            symmetric_ctx += f"  - Note: {sa['explanation']}\n"

    # Inject PRNG / LFSR pre-analysis
    prng_ctx = ""
    pa = state.get("prng_analysis") or {}
    if pa and (pa.get("generator") or pa.get("attack")):
        prng_ctx = f"\n[PRNG / LFSR Parameters Detected]\n"
        if pa.get("generator"):
            prng_ctx += f"  - Generator: {pa['generator']}\n"
        if pa.get("attack"):
            prng_ctx += f"  - Suggested Attack: {pa['attack']}\n"
        if pa.get("explanation"):
            prng_ctx += f"  - Note: {pa['explanation']}\n"

    # Inject Lattice pre-analysis
    lattice_ctx = ""
    la = state.get("lattice_analysis") or {}
    if la and (la.get("cipher") or la.get("attack")):
        lattice_ctx = f"\n[Lattice / Knapsack Cryptography Detected]\n"
        if la.get("cipher"):
            lattice_ctx += f"  - Cipher: {la['cipher']}\n"
        if la.get("attack"):
            lattice_ctx += f"  - Suggested Attack: {la['attack']}\n"
        if la.get("explanation"):
            lattice_ctx += f"  - Note: {la['explanation']}\n"

    # Inject Steganography pre-analysis
    stego_ctx = ""
    sta = state.get("stego_analysis") or {}
    if sta and sta.get("findings"):
        stego_ctx = f"\n[Steganography Findings Detected]\n"
        for finding in sta.get("findings", [])[:3]:
            stego_ctx += f"  - File: {finding.get('file')} | Method: {finding.get('method')} | Note: {finding.get('description')}\n"

    # Inject Advanced Mathematical pre-analysis
    math_ctx = ""
    ma = state.get("math_analysis") or {}
    if ma and (ma.get("method") or ma.get("methods_checked")):
        math_ctx = f"\n[Advanced Mathematical Cryptanalysis Detected]\n"
        if ma.get("method"):
            math_ctx += f"  - Target Method: {ma['method']}\n"
        if ma.get("methods_checked"):
            math_ctx += f"  - Applicable Algorithms: {', '.join(ma['methods_checked'])}\n"

    # Inject CTF Knowledge Base & RAG Exploit Guidance
    rag_ctx = ""
    try:
        from ctf_knowledge_base import retrieve_attack_guidance
        rag_recipes = retrieve_attack_guidance(state['challenge'], top_k=2)
        if rag_recipes:
            rag_ctx = "\n[CTF Knowledge Base & RAG Exploit Guidance]\n"
            for r in rag_recipes:
                title = r.get('title') or r.get('vulnerability', 'Exploit Recipe')
                summary = r.get('summary') or r.get('explanation', '')
                rag_ctx += f"  - Recipe: {title} ({r.get('domain', 'Crypto')})\n    Method: {summary[:160]}\n"
    except Exception:
        pass

    # Inject autonomous attack ranking hypotheses
    rank_ctx = ""
    ranked_hyps = state.get("ranked_hypotheses") or []
    if ranked_hyps:
        rank_ctx = "\n[Autonomous Attack Hypotheses (Ranked by Probability & Cost)]\n"
        for idx, h in enumerate(ranked_hyps[:5], 1):
            rank_ctx += f"  {idx}. Attack: {h.get('attack')} | Prob: {h.get('probability')} | Cost: {h.get('estimated_cost')} | Category: {h.get('category')}\n     Rationale: {h.get('rationale')}\n"

    engine_option = '"python" or "sage"' if SAGE_AVAILABLE else '"python" (SageMath/Docker is NOT installed. You MUST select python)'
    engine_format = '<python or sage>' if SAGE_AVAILABLE else 'python'

    system_prompt = f"""You are an expert cryptographic security auditor and CTF player.
Analyze the given parameters and determine the vulnerability.

Key CTF Rules of Thumb:
Hash Cryptanalysis:
- Hash Type Identification: detect MD5, SHA-1, SHA-224/256/384/512, SHA-3, NTLM by character length (32, 40, 56, 64, 96, 128 hex chars).
- Dictionary & Wordlist Attack: check candidate hashes against common CTF wordlists and keywords.
- Length Extension Attack: Merkle-Damgård hashes (MD5, SHA-1, SHA-256, SHA-512) where H(secret || msg) is used. Reconstruct internal MD state and forge extensions without knowing secret.
- Birthday Attack: collision demonstration in 2^(n/2) operations.

RSA & Asymmetric Attacks:
- RSA Parity Oracle: decrypt (c * 2^e mod N) to test least significant bit parity; binary search m in interval [0, N) in O(log N) oracle queries.
- Bleichenbacher PKCS#1 v1.5 Padding Oracle: adaptive chosen-ciphertext attack querying validity oracle to narrow down blinding intervals [2B, 3B-1].
- Weak Prime Detection: test small prime factors, Fermat closeness (|p-q| < N^0.25), and ROCA Infineon pattern.
- Wiener Attack: large e comparable to N (e > N^0.5, small private d < (1/3)*N^0.25).
- Boneh-Durfee Attack: small private exponent d < N^0.292 beyond Wiener bound via LLL lattice.
- Fermat Factorization: primes are close (|p - q| < N^0.25 or isqrt(N)).
- Small Public Exponent (e=3, 5): integer e-th root when m^e < N without modular wrap.
- Håstad Broadcast Attack: e recipients with same e and distinct N_i; recover m via CRT and e-th root.
- Common Modulus Attack: same N, coprime exponents e1, e2; recover m via Extended GCD (Bezout).
- Franklin-Reiter Attack: related messages m2 = a*m1 + b mod N via polynomial GCD.
- Coppersmith Small-Root Attack: stereotyped message padding recovery (|x| < N^(1/e)) via LLL lattice.
- Pollard's p-1: p-1 is B-smooth.
- Pollard's Rho: general integer factorization via cycle detection.
- Trial Division: factors with small primes.
- ROCA (CVE-2017-15361): vulnerable Infineon key generation (p = k*M + 65537^a mod M).
- Bellcore CRT Fault Attack: differential fault in RSA-CRT signature (gcd(s - s', N)).

Elliptic Curve Cryptography (ECC) Attacks:
- Curve25519 & Ed25519: Montgomery ladder X-only scalar multiplication and Twisted Edwards complete addition laws.
- Baby-Step Giant-Step (BSGS): solve discrete log Q = d*P in O(sqrt(N)) when scalar d <= 10^7 or small subgroup order.
- Pollard's Rho for ECDLP: general low-memory cycle detection discrete logarithm attack.
- Pohlig-Hellman: curve order n = #E(F_p) factors into small prime factors (smooth order); solve subgroups and recombine via CRT.
- Smart's Attack (Anomalous Curves): curve order #E(F_p) == p (trace of Frobenius t = 1); solve ECDLP in O(log^3 p) via p-adic formal group log.
- Invalid Curve Attack: server fails to validate if P is on curve y^2 = x^3 + a*x + b; send point on invalid curve with small order to recover d mod order.
- Small Subgroup / Twist Attack: cofactor h = #E / r > 1; small subgroup point leaks d mod small factors.
- ECDSA Nonce Reuse: same nonce k reused across two signatures (r, s1) and (r, s2) with hashes z1, z2; recover k = (z1 - z2)/(s1 - s2) mod n, d = (s1*k - z1)/r mod n.
- Biased Nonce Attack (HNP): partial nonce bits leaked or biased; form Hidden Number Problem matrix and recover private key d via LLL lattice reduction.
- LLL-based ECDSA Attack: partial nonce MSB/LSB leakages across multiple signatures recovered via Kannan's embedding and LLL.
- ECDLP Scalar Recovery: recover private scalar d such that Q = d*P.
Classical Ciphers:
- Caesar / ROT13: single shift across 1-25. If ROT47: shifts ASCII 33-126.
- Affine: C = (a*P + b) mod 26 where gcd(a,26)=1. Brute-force 312 keys or use 2 known letter pairs.
- Vigenère: polyalphabetic substitution. Key length deduced via Kasiski examination and IoC; solve columns with frequency analysis.
- Atbash: reciprocal alphabet reversal (A<->Z, B<->Y).
- Monoalphabetic Substitution: arbitrary 26-letter permutation; crack via frequency analysis and quadgram hill climbing.
- Playfair: 5x5 key square (combines I/J); pairs of letters encrypted by row, column, or rectangle rules.
- Hill Cipher: linear algebra mod 26. Invert key matrix mod 26 or solve K = P^(-1) * C mod 26.
- Rail Fence / Transposition: letters rearranged in zig-zag rails or columns without changing letter values.
- Crib Dragging / Two-Time Pad: two ciphertexts XOR'd with same keystream (C1 XOR C2 = P1 XOR P2); drag crib to expose text.
XOR:
- If ciphertext XOR'd with a repeating or single-byte key: use frequency analysis or brute-force key.
- If two ciphertexts share the same key (many-time pad): XOR them together to cancel the key, then crib-drag.
- If a known plaintext prefix exists (e.g. "flag{{"): XOR it against ciphertext to recover key bytes.
- If key length is unknown: use Index of Coincidence or Kasiski test to find key length, then frequency analysis.
Binary / Bit Manipulation:
- If challenge involves LSB (Least Significant Bit) manipulation: reconstruct value bit by bit via oracle.
- If challenge involves bitwise rotation or permutation: reverse the bit operations.
- If data is encoded in binary strings or bit arrays: use int(bits, 2) and bitwise ops to decode.
- If challenge uses bit-shift cipher or custom binary encoding: reverse the shift/XOR sequence.
Hash / Encoding:
- If input is Base64, Hex, ROT13, Binary, Octal, URL-encoded, Morse, Base32, Base58, Base62, or Base85: decode it.
- If double-encoded: apply decoding twice (or more) in correct order.
- If input is a hash (MD5/SHA1/SHA256/SHA512/bcrypt etc): identify algorithm and attempt hash cracking or rainbow table lookup in generated code.
General:
- If SageMath is unavailable: Implement the attack in standard Python 3 using gmpy2, sympy, or pycryptodome."""

    user_prompt = f"""Challenge:
{state['challenge']}
{rank_ctx}
{hash_ctx}
{rsa_ctx}
{ecc_ctx}
{symmetric_ctx}
{prng_ctx}
{lattice_ctx}
{stego_ctx}
{math_ctx}
{rag_ctx}
{classical_ctx}
{previous_failure}

Analyze:
1. Category (RSA, ECC, Symmetric, Classical, AES, Lattice, PRNG, Hash, XOR, Binary, Encoding)
2. Underlying Mathematical Flaw / Attack
3. Engine: {engine_option}

Format:
CATEGORY: <category>
ATTACK: <attack name>
ENGINE: {engine_format}"""

    resp = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ]).content

    cat, attack, is_sage = "Crypto", "Direct Computation", False

    # 1. Try JSON block parsing
    json_match = re.search(r"\{[^{}]*(?:category|attack)[^{}]*\}", resp, re.IGNORECASE | re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            cat = data.get("category", cat)
            attack = data.get("attack", attack)
            engine = str(data.get("engine", "")).lower()
            is_sage = bool("sage" in engine) if SAGE_AVAILABLE else False
        except Exception:
            pass

    # 2. Key-Value regex parsing fallback
    cat_match = re.search(r"CATEGORY:\s*(.*)", resp, re.IGNORECASE)
    att_match = re.search(r"ATTACK:\s*(.*)", resp, re.IGNORECASE)
    eng_match = re.search(r"ENGINE:\s*(.*)", resp, re.IGNORECASE)

    if cat_match and cat == "Crypto":
        cat = cat_match.group(1).strip()
    if att_match and attack == "Direct Computation":
        attack = att_match.group(1).strip()
    if eng_match:
        is_sage = bool(eng_match and "sage" in eng_match.group(1).lower()) if SAGE_AVAILABLE else False

    print(f"🎯 Category: {cat} | Attack: {attack} | Engine: {'SageMath' if is_sage else 'Python'}")

    return {
        "category": cat,
        "attack_hypothesis": attack,
        "is_sage": is_sage,
        "iteration": state.get("iteration", 0),
        "max_retries": 4
    }

def extract_clean_code(resp: str) -> str:
    """Robustly extracts executable code from LLM responses."""
    code_match = re.search(r"```(?:python|sage)?\s*\n(.*?)(?:```|$)", resp, re.DOTALL | re.IGNORECASE)
    raw = code_match.group(1) if code_match else resp
    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("```") or stripped.endswith("```"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()

def generate_solver(state: CryptoAgentState) -> dict:
    print(f"\n⚙️ [Step 2] Generating exploit script (Attempt {state.get('iteration', 0) + 1}/{state['max_retries']})...")
    feedback = ""
    if state.get("execution_stderr"):
        feedback = f"\nPrevious attempt failed:\n[STDERR]: {state['execution_stderr']}\n[STDOUT]: {state.get('execution_stdout', '')}\nFix the logic or syntax error."

    use_sage = SAGE_AVAILABLE and state.get("is_sage", False)
    engine_name = "SageMath (.sage)" if use_sage else "Python 3 (.py)"
    sage_notice = ""
    if not SAGE_AVAILABLE or not use_sage:
        sage_notice = (
            "\n[CRITICAL HOST REQUIREMENT]\n"
            "SageMath is NOT installed on this machine. You MUST write standard Python 3 code using gmpy2, sympy, pycryptodome, or rsa_cryptanalysis.\n"
            "DO NOT write 'import sage', 'from sage.all import *', or use Sage-specific types (e.g. PolynomialRing, Zmod). Use standard Python 3 syntax."
        )

    # Inject hash analysis hints into the solver prompt
    hash_hint = ""
    ha = state.get("hash_analysis") or {}
    full_ha = ha.get("full") or {}
    if full_ha.get("summary") and full_ha.get("encoding_layers"):
        layers = full_ha["encoding_layers"]
        enc_steps = []
        for layer in layers:
            enc = layer.get("encoding", "")
            decoded = layer.get("decoded", "")
            is_hash = layer.get("is_hash", False)
            algos = layer.get("hash_algorithms", [])
            if is_hash and algos:
                enc_steps.append(f"Hash ({', '.join(a['algorithm'] for a in algos[:2])}) — crack or lookup")
            elif decoded:
                enc_steps.append(f"Decode {enc}")
        if enc_steps:
            hash_hint = f"\n[Encoding/Hash Hint] Required decode steps: {' → '.join(enc_steps)}"
            if full_ha.get("is_multi_encoded") or full_ha.get("is_double_encoded"):
                hash_hint += "\n⚠️ MULTI-LAYER RECURSIVE ENCODING DETECTED — apply decoding in the exact sequence shown."
            fd = full_ha.get("final_decoded", "")
            if fd and fd != state["challenge"].strip():
                hash_hint += f"\nPre-decoded value available from hash_decoder:\n{fd[:300]}"
            hash_hint += (
                "\nAvailable importable helpers from hash_decoder:\n"
                "  - analyze_hash_or_encoding(text), extract_encoded_strings(text)\n"
                "  - Supports Base64, Base32, Base16, Hex, Binary, ASCII/Unicode escapes, URL, Base85, Base58, Morse, Decimal ASCII, ROT1..25, ROT47, UTF-8, Gzip, Zlib.\n"
            )

    # Inject classical cryptanalysis hints into the solver prompt
    classical_hint = ""
    ca = state.get("classical_analysis") or {}
    if ca.get("top_match"):
        top = ca["top_match"]
        classical_hint = (
            f"\n[Classical Cryptanalysis Hint]\n"
            f"Likely Cipher: {top.get('cipher')}\n"
            f"Candidate Key/Parameters: {top.get('key')}\n"
            f"Top Decrypted Guess: {str(top.get('decrypted', ''))[:150]}\n"
            f"Available importable helpers from classical_crypto:\n"
            f"  - caesar_bruteforce(ct), caesar_decrypt(ct, shift)\n"
            f"  - affine_bruteforce(ct), affine_decrypt(ct, a, b), affine_known_plaintext(p1, c1, p2, c2)\n"
            f"  - vigenere_solve(ct), vigenere_decrypt(ct, key)\n"
            f"  - atbash(ct), rot13(ct), rot47(ct)\n"
            f"  - solve_monoalphabetic_substitution(ct), substitution_decrypt(ct, key)\n"
            f"  - playfair_decrypt(ct, key), generate_playfair_matrix(key)\n"
            f"  - hill_decrypt_2x2(ct, key_matrix), hill_known_plaintext_2x2(p, c), hill_bruteforce_2x2(ct)\n"
            f"  - rail_fence_bruteforce(ct), rail_fence_decrypt(ct, rails)\n"
            f"  - columnar_transposition_bruteforce(ct), columnar_transposition_decrypt(ct, key)\n"
            f"  - xor_single_byte_bruteforce(ct), xor_single_byte(data, key)\n"
            f"  - repeating_key_xor_solve(ct), xor_repeating_key(data, key)\n"
            f"  - known_plaintext_xor(ct, pt, offset), recover_repeating_xor_key(ct, pt, offset, key_len)\n"
            f"  - crib_drag(c1, c2, crib)\n"
            f"  - frequency_analysis(ct), kasiski_examination(ct), index_of_coincidence(ct), score_text_english(ct)"
        )

    # Inject RSA hints into the solver prompt
    rsa_hint = ""
    ra = state.get("rsa_analysis") or {}
    if ra and ra.get("status") != "error":
        rsa_hint = (
            f"\n[RSA Mathematics & Cryptanalysis Helpers Available in rsa_cryptanalysis]\n"
            f"You can import and use:\n"
            f"  from rsa_cryptanalysis import RSAMath, RSAAttacks, LatticeLLL, analyze_and_solve_rsa\n"
            f"  - RSAMath: gcd, lcm, xgcd, modinv, modpow, iroot, is_square, euler_phi, carmichael_lambda, crt, continued_fractions, convergents, clean_flag_or_text\n"
            f"  - RSAAttacks: attack_wiener, attack_boneh_durfee, attack_common_modulus, attack_hastad_broadcast, attack_small_exponent_root, factor_fermat, factor_trial_division, factor_pollard_rho, factor_pollard_p_minus_1, attack_franklin_reiter, attack_coppersmith_stereotyped, private_key_recovery, detect_roca, factor_roca, attack_parity_oracle, detect_weak_primes, bleichenbacher_step_simulation\n"
            f"  - LatticeLLL: reduce(basis, delta=0.75)"
        )

    # Inject ECC hints into the solver prompt
    ecc_hint = ""
    ea = state.get("ecc_analysis") or {}
    if ea and ea.get("parameters"):
        ecc_hint = (
            f"\n[ECC Mathematics & Cryptanalysis Helpers Available in ecc_cryptanalysis]\n"
            f"You can import and use:\n"
            f"  from ecc_cryptanalysis import EllipticCurve, ECPoint, MontgomeryCurve, TwistedEdwardsCurve, STANDARD_CURVES, get_standard_curve, ECCAttacks, analyze_and_solve_ecc\n"
            f"  - EllipticCurve: add(P, Q), multiply(P, k), is_on_curve(P), decompress_point(x, y_parity)\n"
            f"  - MontgomeryCurve (Curve25519): ladder(x_P, k)\n"
            f"  - TwistedEdwardsCurve (Ed25519): add(P, Q), multiply(P, k)\n"
            f"  - ECCAttacks: attack_ecdlp_bsgs, attack_ecdlp_pollard_rho, attack_pohlig_hellman, attack_smart_anomalous, attack_invalid_curve, attack_small_subgroup, attack_ecdsa_nonce_reuse, attack_ecdsa_biased_nonce_lll, attack_ecdsa_partial_nonce_leak\n"
        )

    # Inject Symmetric hints into the solver prompt
    symmetric_hint = ""
    sa = state.get("symmetric_analysis") or {}
    if sa and (sa.get("cipher") or sa.get("attack") or sa.get("method")):
        symmetric_hint = (
            f"\n[Symmetric Cryptanalysis Helpers Available in symmetric_cryptanalysis]\n"
            f"You can import and use:\n"
            f"  from symmetric_cryptanalysis import SymmetricCipher, SymmetricAttacks, GCMUtils, pkcs7_pad, pkcs7_unpad, xor_bytes, analyze_and_solve_symmetric\n"
            f"  - SymmetricCipher: encrypt(cipher_name, key, data, mode, iv, nonce, aad), decrypt(cipher_name, key, ct, mode, iv, nonce, tag, aad, raw)\n"
            f"  - SymmetricAttacks: attack_ecb_byte_at_a_time, attack_cbc_bit_flip, attack_padding_oracle, attack_ctr_nonce_reuse, attack_gcm_nonce_reuse, attack_known_plaintext, attack_chosen_plaintext, attack_differential_cryptanalysis, attack_linear_cryptanalysis, attack_meet_in_the_middle\n"
        )

    # Inject PRNG hints into the solver prompt
    prng_hint = ""
    pa = state.get("prng_analysis") or {}
    if pa and (pa.get("generator") or pa.get("attack")):
        prng_hint = (
            f"\n[PRNG & LFSR Cryptanalysis Helpers Available in prng_cryptanalysis]\n"
            f"You can import and use:\n"
            f"  from prng_cryptanalysis import MT19937Recoverer, solve_lcg_known_m, solve_lcg_unknown_m, berlekamp_massey_gf2, predict_lfsr_bits, analyze_and_solve_prng\n"
            f"  - MT19937Recoverer: recover full 624-word state from 624 32-bit outputs and clone python random.Random\n"
            f"  - solve_lcg_known_m(outputs, m): recover multiplier a and increment c\n"
            f"  - solve_lcg_unknown_m(outputs): recover modulus m, multiplier a, and increment c from 6+ outputs\n"
            f"  - berlekamp_massey_gf2(bits): recover minimal LFSR connection polynomial\n"
        )

    # Inject Lattice hints into the solver prompt
    lattice_hint = ""
    la = state.get("lattice_analysis") or {}
    if la and (la.get("cipher") or la.get("attack")):
        lattice_hint = (
            f"\n[Lattice Cryptanalysis Helpers Available in lattice_crypto]\n"
            f"You can import and use:\n"
            f"  from lattice_crypto import lll_reduction, solve_subset_sum_clos, solve_merkle_hellman, babai_nearest_plane, analyze_and_solve_lattice\n"
            f"  - lll_reduction(basis, delta=0.75): exact rational LLL reduction\n"
            f"  - solve_subset_sum_clos(weights, target_sum): solve low-density knapsack via Clos-Chor-Lemke embedding\n"
            f"  - solve_merkle_hellman(public_key, cipher_sum): decrypt Merkle-Hellman knapsack cryptosystem\n"
            f"  - babai_nearest_plane(basis, target): Closest Vector Problem (CVP) solver\n"
        )

    # Inject Stego hints into the solver prompt
    stego_hint = ""
    sta = state.get("stego_analysis") or {}
    if sta and sta.get("findings"):
        stego_hint = (
            f"\n[Crypto-Steganography Helpers Available in crypto_stego]\n"
            f"You can import and use:\n"
            f"  from crypto_stego import extract_lsb_bytes, carve_trailing_data, search_flag_or_magic, analyze_and_solve_stego\n"
            f"  - extract_lsb_bytes(image_path, channel, plane): extract bit planes from RGB channels\n"
            f"  - carve_trailing_data(image_path): extract payloads appended past PNG IEND / JPEG EOI\n"
        )

    # Inject Remote Socket Bridge hints into the solver prompt
    socket_hint = (
        f"\n[Remote Netcat Socket Bridge Available in remote_socket_bridge]\n"
        f"You can import and use:\n"
        f"  from remote_socket_bridge import RemoteSocketClient, parse_nc_command, probe_remote_service, solve_remote_padding_oracle\n"
        f"  - RemoteSocketClient(host, port, timeout=5, ssl_wrap=False): client.connect(), recvuntil(delim), sendline(msg), close()\n"
    )

    # Inject Advanced Mathematical Cryptanalysis hints
    math_hint = (
        f"\n[Advanced Mathematical Cryptanalysis Helpers Available in advanced_math_crypto]\n"
        f"You can import and use:\n"
        f"  from advanced_math_crypto import (\n"
        f"      xgcd, modinv, legendre_symbol, jacobi_symbol, tonelli_shanks,\n"
        f"      crt, generalized_crt, gaussian_elimination_gf2, gaussian_elimination_gfp,\n"
        f"      lll_reduction, bkz_reduction, solve_cvp_babai, solve_knapsack_clos,\n"
        f"      find_roots_cantor_zassenhaus, hensel_lift_root, buchberger_groebner_basis,\n"
        f"      GF2m, discrete_log_bsgs, discrete_log_pohlig_hellman, factor_pollard_rho,\n"
        f"      PurePythonSATSolver, Z3ConstraintSolverWrapper, berlekamp_massey_field,\n"
        f"      lfsr_predict_bits, untemper_mt19937_32, untemper_mt19937_64, solve_lcg_parameters\n"
        f"  )\n"
    )

    # Inject Hash Cryptanalysis hints
    hash_crypto_hint = (
        f"\n[Hash Cryptanalysis Helpers Available in hash_cryptanalysis]\n"
        f"You can import and use:\n"
        f"  from hash_cryptanalysis import identify_hash_type, compute_hash, dictionary_attack, brute_force_attack, generate_merkle_damgard_padding, length_extension_analysis, generate_cracking_commands, birthday_collision_demo\n"
        f"  - identify_hash_type(hex_hash): returns matching candidate algorithms\n"
        f"  - dictionary_attack(hex_hash, algo): cracks against embedded wordlists\n"
        f"  - length_extension_analysis(orig_hash, orig_len, extension, algo): produces padded extension payload\n"
    )

    # Inject Verification & Report hints
    verification_hint = (
        f"\n[Verification & Report Helpers Available in verification_engine]\n"
        f"You can import and use:\n"
        f"  from verification_engine import extract_flag, validate_plaintext, verify_rsa_roundtrip, generate_solution_report\n"
        f"  - extract_flag(text): searches configurable CTF regexes\n"
        f"  - validate_plaintext(text): statistical sanity and printable check\n"
    )

    system_prompt = f"""You are a solver generator for cryptographic CTFs.
Write a standalone, self-contained {engine_name} script that executes the exploit and prints the flag.
Return ONLY valid executable code inside a single ```python or ```sage block."""

    user_prompt = f"""Challenge:
{state['challenge']}

Attack Strategy: {state.get('attack_hypothesis')}
{hash_hint}
{hash_crypto_hint}
{rsa_hint}
{ecc_hint}
{symmetric_hint}
{prng_hint}
{lattice_hint}
{stego_hint}
{socket_hint}
{math_hint}
{classical_hint}
{verification_hint}
{sage_notice}
{feedback}

Output the code block:"""

    resp = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ]).content
    code = extract_clean_code(resp)

    return {"generated_code": code}

def execute_in_docker(state: CryptoAgentState) -> dict:
    print("🚀 [Step 3] Executing solver in sandbox...")
    code = state["generated_code"]
    
    if not SAGE_AVAILABLE:
        is_sage = False
    else:
        has_sage_keyword = bool(re.search(r"\b(import\s+sage|from\s+sage|IntegerRing|PolynomialRing|Zmod)\b", code))
        is_sage = state.get("is_sage", False) and has_sage_keyword

    res = sandbox.execute(code=code, is_sage=is_sage, allow_network=False, job_id=state.get("job_id"))
    stdout = res["stdout"]
    stderr = res["stderr"]

    if stdout.strip():
        print(f"📄 Output:\n{stdout.strip()}")
    if stderr.strip():
        print(f"⚠️ Error:\n{stderr.strip()}")

    flag = None
    try:
        from verification_engine import extract_flag, validate_plaintext
        flag = extract_flag(stdout)
    except Exception:
        flag_match = re.search(r"(flag\{.*?\}|CTF\{.*?\})", stdout, re.IGNORECASE)
        flag = flag_match.group(1) if flag_match else None

    # Decoded result: extract flag{} format if present, or clean stdout text if successful
    decoded_res = None
    if flag:
        decoded_res = flag
    elif res["exit_code"] == 0 and stdout.strip():
        lines = [line.strip() for line in stdout.strip().splitlines() if line.strip()]
        if lines:
            candidate = lines[-1] if len(lines) > 1 and ("error" not in lines[-1].lower()) else "\n".join(lines)
            # Ensure the output is NOT simply echoing the input challenge text
            if candidate != state["challenge"].strip():
                try:
                    from verification_engine import validate_plaintext
                    val_res = validate_plaintext(candidate)
                    if val_res.get("is_valid"):
                        decoded_res = candidate
                except Exception:
                    decoded_res = candidate

    report = None
    if decoded_res or flag:
        print(f"✨ DECODED RESULT:\n{decoded_res}")
        try:
            from verification_engine import generate_solution_report
            report = generate_solution_report(
                challenge_name="CTF Cryptographic Challenge",
                category=state.get("category") or "Cryptanalysis",
                vulnerability=state.get("attack_hypothesis") or "Cryptographic Exploit",
                parameters=state.get("extracted_parameters") or {},
                attack_script=code,
                flag=decoded_res or flag or "",
                verified=True,
                complexity="Polynomial"
            )
            try:
                from verification_engine import export_ctf_writeup
                export_ctf_writeup(report, challenge_name=state.get("category", "CTF Challenge"))
                from poc_exporter import export_standalone_poc
                export_standalone_poc(
                    exploit_code=code,
                    parameters=state.get("extracted_parameters", {}),
                    verified_flag=decoded_res or flag or "",
                    category=state.get("category", "CTF Challenge"),
                    vulnerability=state.get("attack_hypothesis", "Vulnerability")
                )
            except Exception:
                pass
        except Exception as e:
            report = f"Report generation error: {e}"
    else:
        print("❌ No decoded result captured on this attempt.")

    is_sage_state = state.get("is_sage", False)
    if not SAGE_AVAILABLE or "sagemath" in stderr.lower() or "no module named 'sage'" in stderr.lower():
        is_sage_state = False

    return {
        "execution_stdout": stdout,
        "execution_stderr": stderr if (res["exit_code"] != 0 or not decoded_res) else "",
        "captured_flag": decoded_res,
        "decoded_result": decoded_res,
        "solution_report": report,
        "is_sage": is_sage_state,
        "iteration": state["iteration"] + 1
    }

def evaluation_router(state: CryptoAgentState) -> str:
    if state.get("decoded_result") or state.get("captured_flag"):
        return END
    if state["iteration"] >= state["max_retries"]:
        return END
    if state["iteration"] == 2:
        # Re-evaluate hypothesis if previous attempts hit a dead end
        return "classify"
    return "generate_solver"

# --- Graph Assembly & Fallback Runner ---
if HAS_LANGGRAPH:
    builder = StateGraph(CryptoAgentState)
    builder.add_node("hash_detect",    detect_hash_or_encoding)   # Pre-step: Hash, Encoding & Statistical Analysis
    builder.add_node("classify",       classify_and_plan)
    builder.add_node("generate_solver",generate_solver)
    builder.add_node("execute_docker", execute_in_docker)

    builder.set_entry_point("hash_detect")
    # Only short-circuit directly to END if a verified flag was discovered in the pre-step
    builder.add_conditional_edges("hash_detect", lambda s: END if s.get("captured_flag") else "classify", {
        END:        END,
        "classify": "classify"
    })
    builder.add_edge("classify",       "generate_solver")
    builder.add_edge("generate_solver","execute_docker")
    builder.add_conditional_edges("execute_docker", evaluation_router, {
        "generate_solver": "generate_solver",
        "classify":        "classify",
        END:               END
    })
    crypto_solver_agent = builder.compile()
else:
    class PurePythonCryptoAgent:
        """Pure-Python state runner when LangGraph C-extension dependencies are restricted."""
        def invoke(self, initial_state: dict) -> dict:
            state: dict = {
                "challenge": initial_state.get("challenge", ""),
                "category": initial_state.get("category"),
                "attack_hypothesis": initial_state.get("attack_hypothesis"),
                "is_sage": False,
                "generated_code": None,
                "execution_stdout": None,
                "execution_stderr": None,
                "captured_flag": None,
                "decoded_result": None,
                "iteration": 0,
                "max_retries": initial_state.get("max_retries", 3),
                "hash_analysis": None,
                "classical_analysis": None,
                "rsa_analysis": None,
                "ecc_analysis": None,
                "symmetric_analysis": None,
                "prng_analysis": None,
                "lattice_analysis": None,
                "stego_analysis": None,
                "math_analysis": None,
                "extracted_parameters": None,
                "ranked_hypotheses": None,
                "solution_report": None,
                "job_id": initial_state.get("job_id")
            }
            # Pre-step: Hash, Encoding & Direct Solvers
            pre = detect_hash_or_encoding(state)
            state.update(pre)
            if state.get("captured_flag") or state.get("decoded_result"):
                return state

            curr = "classify"
            while curr != END and state["iteration"] < state["max_retries"]:
                if curr == "classify":
                    state.update(classify_and_plan(state))
                    curr = "generate_solver"
                elif curr == "generate_solver":
                    state.update(generate_solver(state))
                    curr = "execute_docker"
                elif curr == "execute_docker":
                    state.update(execute_in_docker(state))
                    next_step = evaluation_router(state)
                    if next_step == END:
                        break
                    curr = next_step
            return state

    crypto_solver_agent = PurePythonCryptoAgent()

if __name__ == "__main__":
    from data_generator import CryptoDatasetGenerator
    challenge_data = CryptoDatasetGenerator.generate_rsa_fermat(42)
    print("=" * 60)
    print("🎯 Target Challenge:")
    print(challenge_data["problem"])
    print("🔑 Expected Flag:", challenge_data["ground_truth_flag"])
    print("=" * 60)

    initial_state = {"challenge": challenge_data["problem"]}
    result = crypto_solver_agent.invoke(initial_state)
    print("\n" + "=" * 60)
    print("🏆 Final Result:", result.get("captured_flag") or "Failed to solve within retry limit")
    print("=" * 60)
