import os
import re
import shutil
from typing import TypedDict, Optional
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
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

# Detect if SageMath is available either via Docker or native sage binary
SAGE_AVAILABLE = bool(sandbox.has_docker or shutil.which("sage"))

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


# ── Hash, Encoding, Classical & RSA Detection Node ──────────────────────────
def detect_hash_or_encoding(state: CryptoAgentState) -> dict:
    """
    Pre-processing node:
    1. Scans challenge for encoded / hashed strings (Base64, Hex, Morse, hashes).
    2. Runs automated Classical Cryptanalysis ONLY on non-RSA / non-math ciphertexts.
    3. Runs automated RSA Cryptanalysis (Wiener, Fermat, Small e, Common Modulus, etc.)
       when mathematical RSA parameters (N, e, c) are detected.
    Only short-circuits if a genuine verified flag is discovered.
    """
    print("\n🔎 [Pre-Step] Scanning for Hash / Encoding / Classical / RSA patterns…")
    challenge = state["challenge"]
    
    # Check if this is an asymmetric / mathematical RSA challenge
    is_math_rsa = bool(
        re.search(r'\b(N\s*=|modulus|e\s*=|c\s*=|d\s*=|p\s*=|q\s*=|phi\s*=)\b', challenge, re.IGNORECASE)
        and re.search(r'\d{10,}', challenge)
    )

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
    except Exception as e:
        print(f"  ⚠️ Hash/Encoding detection error: {e}")
        hash_analysis = {"full": {}, "substrings": [], "error": str(e)}

    # 2. Classical Cryptanalysis Suite (skip on large-integer RSA/math challenges)
    classical_res = {}
    rsa_res = {}
    verified_flag = None
    solved_category = "Classical Cryptography"
    solved_attack = "Direct Cryptanalysis"
    solved_code = ""

    if not is_math_rsa:
        try:
            from classical_crypto import analyze_and_solve_classical
            candidate_text = hash_analysis.get("full", {}).get("final_decoded") or challenge
            classical_res = analyze_and_solve_classical(candidate_text)
            
            top = classical_res.get("top_match")
            ioc = classical_res.get("index_of_coincidence", 0)
            if top and top.get("decrypted", "").strip() != challenge.strip():
                print(f"  📈 Classical IoC: {ioc} | Top Cipher: {top.get('cipher')}")
            
            flag_pattern = classical_res.get("flag_pattern")
            if flag_pattern and flag_pattern.lower() not in challenge.lower():
                verified_flag = flag_pattern
                cipher_name = top.get('cipher', 'Classical')
                key_info = top.get('key', '')
                solved_category = "Classical Cryptography"
                solved_attack = cipher_name
                solved_code = f"# Solved directly via classical_crypto ({cipher_name})\nprint('{verified_flag}')\n"
                print(f"  🚩 VERIFIED FLAG RECOVERED via {cipher_name} (Key: {key_info}): {verified_flag}")
        except Exception as e:
            print(f"  ⚠️ Classical cryptanalysis error: {e}")
    else:
        print("  🔢 Mathematical / RSA parameters detected — executing RSA Cryptanalysis Suite…")
        try:
            from rsa_cryptanalysis import analyze_and_solve_rsa
            rsa_res = analyze_and_solve_rsa(challenge)
            if rsa_res.get("status") == "solved" and rsa_res.get("flag"):
                pt = rsa_res["flag"]
                atk = rsa_res.get("attack", "RSA Analysis")
                verified_flag = pt
                solved_category = "RSA"
                solved_attack = atk
                solved_code = f"# Solved directly via rsa_cryptanalysis ({atk})\nprint('{pt}')\n"
                print(f"  🚩 VERIFIED RSA FLAG RECOVERED via {atk}: {pt}")
            else:
                print(f"  ℹ️ RSA Analysis initialized. Modulus size: {rsa_res.get('parameters', {}).get('n', 0).bit_length() if rsa_res.get('parameters') else '?'} bits.")
        except Exception as e:
            print(f"  ⚠️ RSA cryptanalysis error: {e}")
            rsa_res = {"status": "error", "error": str(e)}

    result_dict = {
        "hash_analysis": hash_analysis,
        "classical_analysis": classical_res,
        "rsa_analysis": rsa_res
    }
    # Only short-circuit if a genuine verified flag was recovered
    if verified_flag:
        result_dict["captured_flag"] = verified_flag
        result_dict["decoded_result"] = verified_flag
        result_dict["generated_code"] = solved_code
        result_dict["execution_stdout"] = f"🚩 FLAG: {verified_flag}"
        result_dict["category"] = solved_category
        result_dict["attack_hypothesis"] = solved_attack

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
        if full_ha.get("is_double_encoded"):
            hash_ctx += "\n  ⚠️  DOUBLE ENCODING DETECTED — multiple decode passes required."
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

    engine_option = '"python" or "sage"' if SAGE_AVAILABLE else '"python" (SageMath/Docker is NOT installed. You MUST select python)'
    engine_format = '<python or sage>' if SAGE_AVAILABLE else 'python'

    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are an expert cryptographic security auditor and CTF player.
Analyze the given parameters and determine the vulnerability.

Key CTF Rules of Thumb:
RSA & Asymmetric Attacks:
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
- If SageMath is unavailable: Implement the attack in standard Python 3 using gmpy2, sympy, or pycryptodome.<|eot_id|>
<|start_header_id|>user<|end_header_id|>
Challenge:
{state['challenge']}
{hash_ctx}
{rsa_ctx}
{classical_ctx}
{previous_failure}

Analyze:
1. Category (RSA, Classical, AES, ECC, Lattice, PRNG, Hash, XOR, Binary, Encoding)
2. Underlying Mathematical Flaw / Attack
3. Engine: {engine_option}

Format:
CATEGORY: <category>
ATTACK: <attack name>
ENGINE: {engine_format}
<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

    resp = llm.invoke([HumanMessage(content=prompt)]).content

    cat_match = re.search(r"CATEGORY:\s*(.*)", resp, re.IGNORECASE)
    att_match = re.search(r"ATTACK:\s*(.*)", resp, re.IGNORECASE)
    eng_match = re.search(r"ENGINE:\s*(.*)", resp, re.IGNORECASE)

    is_sage = bool(eng_match and "sage" in eng_match.group(1).lower()) if SAGE_AVAILABLE else False
    attack = att_match.group(1).strip() if att_match else "Direct Computation"
    cat = cat_match.group(1).strip() if cat_match else "Crypto"

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
            if full_ha.get("is_double_encoded"):
                hash_hint += "\n⚠️ This is DOUBLE ENCODED — apply decoding in the correct sequence."
            fd = full_ha.get("final_decoded", "")
            if fd and fd != state["challenge"].strip():
                hash_hint += f"\nPre-decoded value available: {fd[:200]}"

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
            f"  - RSAAttacks: attack_wiener, attack_boneh_durfee, attack_common_modulus, attack_hastad_broadcast, attack_small_exponent_root, factor_fermat, factor_trial_division, factor_pollard_rho, factor_pollard_p_minus_1, attack_franklin_reiter, attack_coppersmith_stereotyped, private_key_recovery, detect_roca, factor_roca\n"
            f"  - LatticeLLL: reduce(basis, delta=0.75)"
        )

    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are a solver generator for cryptographic CTFs.
Write a standalone, self-contained {engine_name} script that executes the exploit and prints the flag.
Return ONLY valid executable code inside a single ```python or ```sage block.<|eot_id|>
<|start_header_id|>user<|end_header_id|>
Challenge:
{state['challenge']}

Attack Strategy: {state.get('attack_hypothesis')}
{hash_hint}
{rsa_hint}
{classical_hint}
{sage_notice}
{feedback}

Output the code block:
<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

    resp = llm.invoke([HumanMessage(content=prompt)]).content
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

    res = sandbox.execute(code=code, is_sage=is_sage, allow_network=False)
    stdout = res["stdout"]
    stderr = res["stderr"]

    if stdout.strip():
        print(f"📄 Output:\n{stdout.strip()}")
    if stderr.strip():
        print(f"⚠️ Error:\n{stderr.strip()}")

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
                decoded_res = candidate

    if decoded_res:
        print(f"✨ DECODED RESULT:\n{decoded_res}")
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

# --- Graph Assembly ---
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
