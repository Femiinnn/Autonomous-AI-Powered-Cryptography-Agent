<div align="center">

# 🔐 Crypto CTF Agent

### An Autonomous Cryptanalysis Agent powered by LangGraph, Llama-3, and a Dockerized SageMath Sandbox

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2%2B-orange)](https://github.com/langchain-ai/langgraph)
[![Llama-3](https://img.shields.io/badge/Llama--3.1-8B%20Instruct-purple?logo=meta)](https://llama.meta.com/)
[![Docker](https://img.shields.io/badge/Docker-Sandbox-blue?logo=docker)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

## 🎯 Aim

**Crypto CTF Agent** is a fully autonomous AI system designed to **identify and exploit cryptographic vulnerabilities** in Capture The Flag (CTF) competition challenges — without human intervention.

Given a raw challenge description (problem statement, ciphertext, public parameters, or attached files), the agent will:

1. **Classify** the cryptographic category and pinpoint the underlying mathematical flaw
2. **Generate** a targeted exploit script in Python or SageMath
3. **Execute** the script inside an isolated Docker sandbox
4. **Recover and return** the decoded output (plaintext, decrypted secret, or `flag{...}` format)

The agent is built on a **reinforcement learning foundation**: a GRPO (Group Relative Policy Optimization) fine-tuning pipeline trains Llama-3 to solve challenges with verifiable Docker execution rewards — no human-annotated preference data needed.

> The core insight is treating **code execution correctness as a reward signal** — if the Docker sandbox extracts the valid plaintext or flag, the model's reasoning is rewarded; if it crashes, the error is fed back for self-correction.

---

## 🏗️ Architecture

The agent is a **LangGraph state machine** combining deterministic mathematical engines with reinforcement-learned LLM reasoning in a self-correcting loop:

```
 ┌─────────────────────────────────────────────────────────┐
 │                   CryptoAgentState                      │
 │   challenge · category · attack · is_sage · iteration   │
 │   generated_code · stdout · stderr · decoded_result     │
 │   hash_analysis · classical_analysis · rsa_analysis     │
 └─────────────────────────────────────────────────────────┘
                            │
                            ▼
 ┌─────────────────────────────────────────────────────────┐
 │                [Pre-Step] hash_detect                   │
 │  Multi-Layer Hash/Encoding Decoder (hash_decoder.py)   │
 │  Classical Cryptanalysis Engine    (classical_crypto.py)│
 │  RSA Mathematical Pre-Analysis    (rsa_cryptanalysis.py)│
 └──────────────────────────┬──────────────────────────────┘
                            │ (verified flag found? -> END)
                            ▼
                  ┌──────────────────┐
                  │  1. classify     │  ◄──────────────────────────┐
                  │  Llama-3 reads   │                             │ re-classify
                  │  challenge &     │                             │ (iteration==2)
                  │  math parameters │                             │
                  └────────┬─────────┘                             │
                           │                                       │
                           ▼                                       │
                  ┌──────────────────┐       error/retry           │
                  │  2. generate     │ ◄───────────────────────────┤
                  │  Llama-3 writes  │                             │
                  │  exploit code    │                             │
                  └────────┬─────────┘                             │
                           │                                       │
                           ▼                                       │
                  ┌──────────────────┐                             │
                  │  3. execute      │                             │
                  │  DockerSandbox   │                             │
                  │  runs the script │                             │
                  └────────┬─────────┘                             │
                           │                                       │
                           ▼                                       │
                    ┌─────────────┐    flag found      ┌──────┐    │
                    │  evaluation │ ─────────────────► │  END │    │
                    │  router     │    max retries     └──────┘    │
                    └─────────────┘ ─────────────────► END         │
                           │                                       │
                           └───────────────────────────────────────┘
```

### Node Details

#### `detect_hash_or_encoding` (Pre-Step)
- Scans challenge text for 12+ encoding layers (Base64/32/58/62/85, Hex, Binary, Octal, Morse, URL, HTML, ROT13/47)
- Identifies cryptographic hash fingerprints (MD5, SHA-1/256/512, NTLM, CRC32, bcrypt, Argon2)
- Performs statistical profiling: **Index of Coincidence (IoC)**, **$\chi^2$ frequency analysis**, and **Kasiski examination**
- Automatically executes RSA parameter pre-testing (**Wiener**, **Fermat**, **Small $e$ root**, **Common Modulus**, **ROCA**) on mathematical challenges

#### `classify_and_plan`
- Sends challenge parameters + pre-analysis report to **Llama-3** (Llama-3.1-8B-Instruct) using specialized CTF cryptanalysis prompts
- Determines: `CATEGORY` (RSA, Classical, AES, ECC, PRNG, Hash, XOR, Binary), `ATTACK`, and `ENGINE` (Python or SageMath)
- On retry: injects previous traceback and failed hypotheses as negative feedback

#### `generate_solver`
- Prompts Llama-3 to write a **standalone, self-contained exploit script**
- Imports pre-built cryptanalysis helpers from `rsa_cryptanalysis.py` and `classical_crypto.py`
- On retry: attaches `[STDERR]` and `[STDOUT]` from the failed container execution for self-correction

#### `execute_in_docker`
- Runs the generated exploit inside an **ephemeral Docker container** (SageMath + Python 3 + gmpy2 + pycryptodome + pwntools + z3)
- Sandboxed with `--network=none`, `--memory=1g`, and strict 30-second timeout
- Recovers flag or decoded plaintext output, returning error tracebacks if execution fails

#### Evaluation Router
| Condition | Action |
|---|---|
| Decoded result or `flag{...}` found | → `END` ✅ |
| `iteration == 2` (stuck) | → `classify` (re-hypothesize attack) |
| `iteration < max_retries` | → `generate_solver` (fix script) |
| `iteration >= 4` | → `END` ❌ |

---

## 🔓 Supported Cryptographic Attacks

### A. RSA Cryptanalysis Suite (`rsa_cryptanalysis.py`)

#### Essential RSA Mathematics
The suite includes an independent, pure-Python and `gmpy2`-accelerated mathematical foundation:
- **Euler's Totient Function**: $\phi(N) = (p-1)(q-1)$
- **Carmichael Function**: $\lambda(N) = \text{lcm}(p-1, q-1)$
- **Modular Exponentiation & Inverse**: Fast `pow(base, exp, mod)` and Extended Euclidean inverse
- **Extended Euclidean Algorithm (xgcd)**: Computes Bézout coefficients satisfying $a \cdot x + b \cdot y = \gcd(a, b)$
- **Chinese Remainder Theorem (CRT)**: Reconstructs integers from system of modular congruences
- **Integer Roots & Prime Factorization**: Exact $e$-th roots over integers and Pollard / Fermat factoring
- **Continued Fractions**: Continued fraction expansions and convergent generators for rational approximations
- **Lattice Reduction (LLL)**: Pure-Python and `gmpy2` implementation of the Lenstra–Lenstra–Lovász basis reduction algorithm

#### Attack Matrix (15 Algorithms)
| Attack / Algorithm | Trigger Condition / Vulnerability | Method & Complexity |
|---|---|---|
| **Integer Factorization Recovery** | Given prime factors $p, q$ | Computes $\phi(N) = (p-1)(q-1)$, $d = e^{-1} \pmod{\phi(N)}$, decrypts $m = c^d \pmod N$ |
| **Trial Division** | Modulus $N$ contains small prime factors | Checks factors up to $2 \times 10^6$ |
| **Fermat Factorization** | Close primes: $|p - q| < N^{1/4}$ | Expresses $N = a^2 - b^2 = (a-b)(a+b)$ |
| **Pollard's Rho** | Composite integer factorization | Cycle detection using $f(x) = (x^2 + c) \pmod N$ |
| **Pollard's $p-1$** | Smooth prime factors | Succeeds when $p-1$ has small prime factors |
| **Wiener Attack** | Small private exponent: $d < \frac{1}{3} N^{1/4}$ | Continued fraction convergents of $e/N$ |
| **Håstad's Broadcast Attack** | Same $m$ sent to $e$ recipients with exponent $e$ | Solves $C = m^e \pmod{\prod N_i}$ via CRT, then extracts exact $e$-th root |
| **Common Modulus Attack** | Same $N$, two coprime exponents $e_1, e_2$ | Extended Euclidean: $s_1 e_1 + s_2 e_2 = 1 \implies c_1^{s_1} c_2^{s_2} \equiv m \pmod N$ |
| **Franklin-Reiter Attack** | Related messages: $m_2 = a \cdot m_1 + b \pmod N$ | Polynomial resultant / GCD root recovery |
| **Coppersmith Small-Root Attack** | Stereotyped messages ($m = \text{prefix} \parallel x$, $|x| < N^{1/e}$) | Bivariate polynomial small root finding via LLL lattice reduction |
| **Partial Key Exposure** | Lower bits of $d$ or $p$ leaked | Recovers full private key using Hensel lifting / lattice |
| **Bellcore CRT Fault Attack** | Fault injected during RSA-CRT computation | Recovers prime factor $p = \gcd(S - S', N)$ from valid & faulty signatures |
| **Low Public Exponent (Cube Root)** | Small $e$ ($e=3, 5$) and $m^e < N$ | Direct exact integer $e$-th root without modular wrap |
| **Boneh-Durfee Attack** | Small private exponent beyond Wiener bound ($d < N^{0.292}$) | Sub-lattice basis reduction using LLL |
| **ROCA Detection & Factorization** | Vulnerable Infineon RSA firmware (CVE-2017-15361) | Fast residue subgroup fingerprinting & discrete log factorization |

### B. Elliptic Curve Cryptography (ECC) Suite (`ecc_cryptanalysis.py`)

#### Essential ECC Mathematics
The suite includes an independent, pure-Python and `gmpy2`-accelerated Weierstrass curve engine:
- **Short Weierstrass Curve Arithmetic**: Supports curves of form $y^2 \equiv x^3 + a x + b \pmod p$ with discriminant $\Delta = -16(4a^3 + 27b^2) \not\equiv 0 \pmod p$
- **ECPoint Group Operations**: Constant-time affine point addition $P + Q$, doubling $2P$, and point at infinity $\mathcal{O}$
- **Fast Double-and-Add Scalar Multiplication**: Computes $k \cdot P$ in $O(\log k)$ group additions
- **Modular Square Roots**: Tonelli-Shanks algorithm for point decompression $(x, y)$ from $x$ and sign bit
- **Order Determination & Smooth Subgroups**: Order factoring and cofactor decomposition for subgroup validation

#### Attack Matrix (10 Algorithms & Lattice HNP)
| Method / Algorithm | Application & Vulnerability | Mathematical Technique & Complexity |
|---|---|---|
| **Elliptic Curve Discrete Logarithm Problem (ECDLP)** | Recover private scalar $d$ from $Q = d \cdot G$ | Multi-strategy auto-solver selecting BSGS, Pohlig-Hellman, or Pollard's Rho |
| **Baby-Step Giant-Step (BSGS)** | Solve discrete logarithms for small/bounded scalars | Space-time tradeoff in $O(\sqrt{N})$ group steps using hash lookup table |
| **Pollard's Rho for ECDLP** | Discrete logarithm attack | Low-memory Floyd's cycle-finding algorithm over pseudo-random point walks |
| **Pohlig-Hellman Attack** | Weak subgroup order ($n = \#E(\mathbb{F}_p)$ is smooth) | Solves DLP in prime-power subgroups and recombines via Chinese Remainder Theorem (CRT) |
| **Invalid Curve Attack** | Exploit missing curve point validation | Submits points on invalid curve $y^2 \equiv x^3 + ax + b' \pmod p$ with small order to recover $d \pmod{\text{ord}}$ |
| **Small Subgroup Attack** | Weak subgroup parameters / non-prime order | Queries points in small cofactor subgroup $r \mid h$ to extract partial scalar bits $d \pmod r$ |
| **Smart's Attack** | Anomalous elliptic curves ($\#E(\mathbb{F}_p) = p$) | Hensel lift of curve & points to $\mathbb{Z}/p^2\mathbb{Z}$ and $p$-adic formal group logarithm in $O(\log^3 p)$ |
| **Nonce Reuse Attack** | Recover ECDSA private key from duplicate nonce $k$ | Algebraic recovery: $k = (z_1 - z_2)(s_1 - s_2)^{-1} \pmod n$, $d = (s_1 k - z_1)r^{-1} \pmod n$ |
| **Biased Nonce Attack** | Lattice-based key recovery from partially biased nonces | Formulates Hidden Number Problem (HNP) and solves via Lenstra–Lenstra–Lovász (LLL) lattice reduction |
| **LLL-based ECDSA Attack** | Recover private keys from partial nonce leakage | Multi-signature Kannan embedding matrix reduction with LLL to uncover secret scalar $d$ |

### C. Classical Cryptanalysis Suite (`classical_crypto.py`)
| Cipher / Method | Description | Algorithm & Technique |
|---|---|---|
| **Caesar Cipher** | Brute force all 25 shifts | Ranked by quadgram & Chi-squared English scoring |
| **Affine Cipher** | $C = (a \cdot P + b) \pmod{26}$ | 312 key brute-force & known-plaintext modular inverse solver |
| **Vigenère Cipher** | Polyalphabetic substitution | Automated Kasiski factor analysis, IoC, & per-column frequency solver |
| **Atbash Cipher** | Reciprocal alphabet inversion ($A \leftrightarrow Z$) | Instant symmetric decode |
| **ROT13 & ROT47** | Rotation substitution | ROT13 (letters) & ROT47 (printable ASCII 33–126) |
| **Monoalphabetic Substitution** | Arbitrary 26-letter substitution | Hill climbing / simulated annealing with quadgram language model |
| **Playfair Cipher** | $5 \times 5$ digraph matrix cipher | Matrix generator, digraph decryption, and shape analyzer |
| **Hill Cipher** | Modular linear algebra over $\mathbb{Z}_{26}$ | $2 \times 2$ & $3 \times 3$ matrix inverse, known-plaintext, & brute-force |
| **Rail Fence Cipher** | Zig-zag transposition cipher | Variable rail fence solver ($2 \le k \le 30$) with n-gram scoring |
| **Columnar Transposition** | Row-write, column-read transposition | Permutation brute-force for key sizes $2 \le k \le 8$ |
| **Single-Byte XOR** | 256-key XOR brute force | Byte frequency scoring & automatic `flag{...}` regex matching |
| **Repeating-Key XOR** | Multi-byte keystream XOR | Normalized Hamming distance keysize detection & transposed block solver |
| **Known-Plaintext XOR** | Key recovery from known prefix | Recovers key slice from known plaintexts (`flag{`, headers) & repeats |
| **Frequency Analysis** | Monogram counts & percentages | Chi-squared ($\chi^2$) distance metric against standard English corpus |
| **Kasiski Examination** | Polyalphabetic key length deduction | Repeated n-gram distance analysis & factor frequency ranking |
| **Index of Coincidence (IoC)** | Text statistical randomness test | Calculates $\text{IC} = \frac{\sum f_i(f_i-1)}{N(N-1)}$ (English $\approx 0.067$) |
| **N-gram Scoring** | Fluent language evaluation | Quadgram, trigram, and bigram log-probability language models |
| **Crib Dragging** | Two-time pad / key reuse attack | Slides known crib across $C_1 \oplus C_2 = P_1 \oplus P_2$ to reveal plaintext |

### D. Symmetric Cryptography Suite (`symmetric_cryptanalysis.py`)

#### Supported Ciphers & Modes
The suite features a robust pure-Python & `pycryptodome` cryptographic engine:
- **Block Ciphers**: AES-128, AES-192, AES-256, DES, 3DES (Triple DES), and Blowfish
- **Stream Ciphers**: ChaCha20 and RC4 (ARC4)
- **Operational Modes**: Electronic Codebook (ECB), Cipher Block Chaining (CBC), Cipher Feedback (CFB), Output Feedback (OFB), and Counter Mode (CTR)
- **Authenticated Encryption**: Galois/Counter Mode (AES-GCM) with pure-Python GHASH polynomial arithmetic over $\text{GF}(2^{128})$ ($x^{128} + x^7 + x^2 + x + 1$)

#### Attack Matrix (10 Core Cryptanalysis Methods)
| Method / Algorithm | Application & Vulnerability | Cryptanalytic Technique & Complexity |
|---|---|---|
| **ECB Byte-at-a-Time Attack** | Adaptive chosen-prefix / secret suffix recovery | Discovers block size, validates ECB determinism, and brute-forces secret bytes one-by-one via dictionary block matching |
| **CBC Bit-Flipping Attack** | Predictable block cipher malleability | Flips bit positions in ciphertext block $C_{i-1}$ or IV to precisely inject desired bytes into decrypted plaintext block $P_i$: $C_{i-1}'[k] = C_{i-1}[k] \oplus P_i[k] \oplus P_i'[k]$ |
| **Padding Oracle Attack** | PKCS#7 error side-channel leakage | Full ciphertext decryption block-by-block, byte-by-byte via Vaudenay's oracle probe without requiring the encryption key |
| **CTR Nonce Reuse Attack** | Two-time pad / stream cipher keystream reuse | Algebraic keystream cancellation $C_1 \oplus C_2 = P_1 \oplus P_2$; recovers keystream via known plaintext or statistical crib-dragging |
| **GCM Nonce Reuse Attack** | Reused nonce in AES-GCM | Extracts plaintext keystream XOR and sets up tag difference polynomial $T_1 \oplus T_2 = \text{GHASH}_H(C_1) \oplus \text{GHASH}_H(C_2)$ to recover authentication subkey $H$ in $\text{GF}(2^{128})$ |
| **Known-Plaintext Attack (KPA)** | Known $(P, C)$ pairs | Derives stream cipher keystream $KS = P \oplus C$, or brute-forces small key spaces matching $E_K(P) = C$ |
| **Chosen-Plaintext Attack (CPA)** | Oracle capability / mode distinction | Submits repeated block probes to distinguish ECB vs CBC mode, detect fixed IVs, and extract secret prefix/suffix boundaries |
| **Differential Cryptanalysis** | Non-uniform difference propagation | Computes Difference Distribution Table (DDT) of S-Boxes: $\text{DDT}[\Delta X][\Delta Y] = \#\{X : S(X) \oplus S(X \oplus \Delta X) = \Delta Y\}$, finding optimal high-probability differential characteristics |
| **Linear Cryptanalysis** | Linear approximation of non-linear primitives | Computes Linear Approximation Table (LAT) and Matsui's Piling-Up Lemma to identify maximum correlation bias $\epsilon = |p - 1/2|$ and extract key bits |
| **Meet-in-the-Middle Attack (MITM)** | Double encryption $C = E_{K_2}(E_{K_1}(P))$ (e.g. 2DES) | Precomputes forward table $\{E_{K_1}(P) : K_1\}$ in $O(2^k)$ and matches against decrypted intermediate states $D_{K_2}(C)$ |
| Cipher / Method | Description | Algorithm & Technique |
|---|---|---|
| **Caesar Cipher** | Brute force all 25 shifts | Ranked by quadgram & Chi-squared English scoring |
| **Affine Cipher** | $C = (a \cdot P + b) \pmod{26}$ | 312 key brute-force & known-plaintext modular inverse solver |
| **Vigenère Cipher** | Polyalphabetic substitution | Automated Kasiski factor analysis, IoC, & per-column frequency solver |
| **Atbash Cipher** | Reciprocal alphabet inversion ($A \leftrightarrow Z$) | Instant symmetric decode |
| **ROT13 & ROT47** | Rotation substitution | ROT13 (letters) & ROT47 (printable ASCII 33–126) |
| **Monoalphabetic Substitution** | Arbitrary 26-letter substitution | Hill climbing / simulated annealing with quadgram language model |
| **Playfair Cipher** | $5 \times 5$ digraph matrix cipher | Matrix generator, digraph decryption, and shape analyzer |
| **Hill Cipher** | Modular linear algebra over $\mathbb{Z}_{26}$ | $2 \times 2$ & $3 \times 3$ matrix inverse, known-plaintext, & brute-force |
| **Rail Fence Cipher** | Zig-zag transposition cipher | Variable rail fence solver ($2 \le k \le 30$) with n-gram scoring |
| **Columnar Transposition** | Row-write, column-read transposition | Permutation brute-force for key sizes $2 \le k \le 8$ |
| **Single-Byte XOR** | 256-key XOR brute force | Byte frequency scoring & automatic `flag{...}` regex matching |
| **Repeating-Key XOR** | Multi-byte keystream XOR | Normalized Hamming distance keysize detection & transposed block solver |
| **Known-Plaintext XOR** | Key recovery from known prefix | Recovers key slice from known plaintexts (`flag{`, headers) & repeats |
| **Frequency Analysis** | Monogram counts & percentages | Chi-squared ($\chi^2$) distance metric against standard English corpus |
| **Kasiski Examination** | Polyalphabetic key length deduction | Repeated n-gram distance analysis & factor frequency ranking |
| **Index of Coincidence (IoC)** | Text statistical randomness test | Calculates $\text{IC} = \frac{\sum f_i(f_i-1)}{N(N-1)}$ (English $\approx 0.067$) |
| **N-gram Scoring** | Fluent language evaluation | Quadgram, trigram, and bigram log-probability language models |
| **Crib Dragging** | Two-time pad / key reuse attack | Slides known crib across $C_1 \oplus C_2 = P_1 \oplus P_2$ to reveal plaintext |

### E. Encoding & Data Transformation Suite (`hash_decoder.py`)

#### Supported Encodings & Transformations
| Encoding / Transformation | Supported Formats & Variants | Decapsulation Technique & Behavior |
|---|---|---|
| **Base64 / Base32 / Base16** | Standard Base64, URL-safe Base64, RFC 4648 Base32, Base32hex, and RFC 4648 Base16 | Automatic padding calculation (`=`), byte-stream translation, and nested stream extraction |
| **Hexadecimal** | Continuous hex, space-separated, colon-separated, C/Python escapes (`\x..`), and array literals (`[0x..]`) | Normalized byte conversion, unhexlify parsing, and raw byte stream preservation |
| **Hex-to-Bytes Conversion** | Raw non-printable binary bytes, packed byte sequences | Bridges binary payloads directly into downstream Gzip/Zlib decompressors or cipher engines |
| **Binary** | Continuous 8-bit/7-bit, space-separated bytes, `0b` binary literals | Byte aggregation, alignment normalization, and ASCII/UTF-8 decoding |
| **ASCII / Unicode** | `\uXXXX`, `\UXXXXXXXX`, HTML/XML numeric character entities (`&#102;`, `&#x66;`), slash escapes | Python `unicode_escape` decoding and HTML entity unescaping |
| **URL Encoding** | Standard percent encoding (`%XX`), plus-as-space, and IIS Unicode (`%uXXXX`) | Recursive `unquote_plus` and Unicode codepoint replacement |
| **Base85** | RFC 1924 / Git Base85 (`b85`) and Ascii85 / Adobe Base85 (`<~...~>`, `z` zero abbreviation) | Dual-variant decoding (`b85decode` + `a85decode`) with binary payload handoff |
| **Base58** | Bitcoin, Ripple, and Flickr alphabets | Multi-alphabet dictionary parsing with leading-zero preservation |
| **Morse Code** | International Morse code with `.`, `-`, `_`, `/`, `|` | Word tokenization and reverse mapping to alphanumeric characters |
| **Decimal ASCII** | Space/comma/semicolon/dash-separated integer byte values (`102 108 97 103`) | Value range filtering (0–255), printable density scoring, and ASCII char reconstruction |
| **ROT Transformations** | All 25 Caesar shifts (ROT1–ROT25), ROT47 printable ASCII (33–126), and ROT5 digits | Exhaustive shift evaluation with automated English quadgram / flag-regex pattern scoring |
| **UTF-8 & Mojibake** | Multi-byte UTF-8 streams and double-encoded Latin1/CP1252 text | Mojibake recovery (`encode('latin1').decode('utf-8')`) and UTF-8 validation |
| **Gzip / Zlib** | Gzip streams (`\x1f\x8b`), Zlib streams (`\x78\x9c`, `\x78\x01`, `\x78\xda`), raw Deflate | Automated stream detection and headerless/header-based decompression |

#### Recursive Multi-Layer Decoding Pipeline
CTF challenges frequently wrap flags in multiple layers of encoding (e.g. `URL → Base64 → Gzip → Hex → Decimal ASCII`). The autonomous engine:
- Seamlessly transitions between text strings and raw binary byte representations.
- Recursively peels up to **15 nested encoding layers** in a single pass.
- Employs SHA-256 cryptographic state fingerprinting to prevent infinite loops and cyclic transformations.
- Immediately captures and verifies flags when standard CTF flag formats (`flag{...}`, `ctf{...}`) are exposed.

---

### F. PRNG & LFSR Cryptanalysis Suite (`prng_cryptanalysis.py`)

Specialized automated cryptanalysis for pseudo-random number generators and linear feedback shift registers commonly deployed in CTF challenges:

#### Attack Matrix & Methods

| Method | Application | Algorithmic Mechanism |
|---|---|---|
| **MT19937 State Untwister** | Full 624-word state recovery | Inverts 32-bit bitwise temper operations (`>>11`, `<<7 & 0x9d2c5680`, `<<15 & 0xefc60000`, `>>18`) to recover the exact 624 internal 32-bit state words |
| **Python `random` Cloner** | Predict all future outputs | Injects reconstructed MT19937 state array into `random.Random().setstate()` to perfectly emulate the remote Python PRNG |
| **LCG Known Modulus Solver** | Parameter recovery ($a, c$) | Solves multiplier $a = (s_2 - s_1)(s_1 - s_0)^{-1} \pmod m$ and increment $c = s_1 - a \cdot s_0 \pmod m$ |
| **LCG Unknown Modulus Solver** | Parameter recovery ($m, a, c$) | Forms trajectory determinants $t_n = s_{n+1} - s_n$; computes $u_n = |t_{n+2} t_n - t_{n+1}^2|$ and extracts modulus via multi-sample $\gcd(u_1, u_2, \dots)$ |
| **Truncated LCG Solver** | Hidden state bits | Formulates hidden lower bits as a bounded lattice problem solved via LLL basis reduction |
| **Berlekamp-Massey over $\text{GF}(2)$** | Minimal polynomial of LFSR | Determines the shortest LFSR connection polynomial generating observed keystream sequence in $O(L^2)$ operations |
| **LFSR Keystream Predictor** | Keystream forecasting | Synthesizes future and past keystream bits using the recovered feedback recurrence equation |

---

### G. Lattice Cryptography Suite (`lattice_crypto.py`)

A pure-Python rational lattice mathematics and cryptanalysis engine independent of external C/C++ libraries, featuring post-quantum lattice primitives:

#### Attack Matrix & Methods

| Method | Application | Algorithmic Mechanism |
|---|---|---|
| **Exact Rational LLL Reduction** | Basis reduction | Implements Lenstra-Lenstra-Lovász algorithm over $\mathbb{Q}$ using exact `fractions.Fraction` Gram-Schmidt orthogonalization and Lovász condition $(\delta = 0.75)$ |
| **Clos-Chor-Lemke Knapsack Solver** | Low-density Subset Sum | Embeds knapsack weights $a_i$ and target sum $S$ into an $(n+1) \times (n+1)$ lattice; recovers binary solutions $m \in \{0, 1\}^n$ for density $d < 0.9408$ |
| **Merkle-Hellman Cryptanalysis** | Public-key knapsack | Decrypts superincreasing sequences disguised by modular multiplier $W$ and modulus $M$ through orthogonal lattice reduction |
| **Babai's Nearest Plane (CVP)** | Closest Vector Problem | Finds closest lattice point to target non-lattice vector $v$ using Gram-Schmidt basis projection |
| **NTRU Circulant Lattice Solver** | Post-quantum NTRU | Recovers small private key polynomials $(f, g)$ and decrypts ciphertexts via Coppersmith-Shamir $2N \times 2N$ circulant basis reduction |
| **Polynomial Ring Convolution** | Ring arithmetic | Computes exact polynomial multiplication in quotient ring $\mathbb{Z}_q[x]/(x^N - 1)$ for NTRU encryption/decryption validation |
| **LWE Kannan Embedding Solver** | Learning With Errors | Solves secret vector $s$ from $(A, b = As + e \pmod q)$ by embedding problem into an $(m + n + 1)$-dimensional Kannan lattice |

---

### H. Crypto-Steganography Suite (`crypto_stego.py`)

Automated digital asset inspection and payload carving for multi-stage cryptographic challenges:

#### Attack Matrix & Methods

| Method | Application | Algorithmic Mechanism |
|---|---|---|
| **LSB Bit Plane Extractor** | Concealed binary payloads | Inspects least significant bit (LSB) planes across Red, Green, Blue, and Alpha channels of image assets |
| **Trailing Payload Carver** | Appended ciphertexts / flags | Detects and extracts payloads concatenated past standard end-of-file markers: PNG `IEND` chunk and JPEG End-of-Image (`\xff\xd9`) |
| **Embedded Archive Carving** | Polyglot / nested files | Scans binary buffers for ZIP (`PK\x03\x04`), Gzip (`\x1f\x8b`), 7z, and tar headers with automated decompression |

---

### I. Live Network Netcat Socket Bridge (`remote_socket_bridge.py`)

Pure-Python interactive TCP client designed to automate dialogue with remote netcat CTF challenge servers:

- **Configurable Line-Buffering & Timeouts**: Robust `recvuntil(delim)`, `recvline()`, and `sendline(data)` semantics.
- **SSL / TLS Wrap Support**: Connects to both raw TCP netcat services and encrypted SSL CTF endpoints.
- **Automated Service Probing**: Interacts with remote banners, parses prompts, and feeds oracle responses into agent solver pipelines.
- **Remote Oracle Automation**: Drives live remote padding oracle attacks and bit-flipping queries over network sockets.

---

### J. CTF Knowledge Base & RAG Exploit Retrieval (`ctf_knowledge_base.py`)

Curated repository of exploit recipes and cryptanalysis guidance across all cryptographic domains:

- Covers PRNG, LFSR, Lattice Knapsack, RSA, ECC, Symmetric modes, Stream ciphers, and Classical cryptography.
- **Query-Based Guidance Retrieval**: Dynamically injects targeted exploit templates, mathematical formulas, and trigger patterns into the LLM context during `classify_and_plan`.

---

### K. Advanced Mathematical Cryptanalysis Suite (`advanced_math_crypto.py`)

Comprehensive computational algebra, lattice reduction, and constraint-solving engine covering 18 advanced mathematical disciplines:

| # | Discipline | Mathematical Formulation & Algorithmic Implementation |
|---|---|---|
| 1 | **Lattice-based Cryptanalysis** | Shortest Vector Problem (SVP), Closest Vector Problem (CVP via Babai's Nearest Plane), Knapsack / Subset Sum (Clos-Chor-Lemke), Coppersmith small roots |
| 2 | **LLL Lattice Reduction** | Exact rational Lenstra–Lenstra–Lovász basis reduction over $\mathbb{Q}$ with Lovász condition $\delta = 0.75$ and Gram-Schmidt orthogonalization |
| 3 | **BKZ Lattice Reduction** | Block Korkine-Zolotarev reduction: sweeps over local projected blocks of size $\beta \le \text{block\_size}$, finds shortest vector, and re-reduces with LLL |
| 4 | **Polynomial Factorization** | Over $\mathbb{F}_p$ / $\mathbb{Z}_p$: Cantor-Zassenhaus algorithm splitting factors via $(x+a)^{(p-1)/2} - 1$, distinct-degree factorization |
| 5 | **Gröbner Basis Methods** | Buchberger's algorithm computing Gröbner basis $G$ of multivariate polynomial ideals with multivariate polynomial division and S-polynomial reduction |
| 6 | **Modular Arithmetic** | Extended Euclidean Algorithm (XGCD), modular inverse, Jacobi and Legendre symbols, Tonelli-Shanks quadratic residue square root solver |
| 7 | **Finite Field Arithmetic** | Field operations in $\mathbb{F}_p$ and binary extension fields $\mathbb{F}_{2^m}$ with irreducible polynomial reduction (e.g. AES $\text{GF}(2^8)$, GCM $\text{GF}(2^{128})$) |
| 8 | **Discrete Logarithm Algorithms** | Baby-Step Giant-Step in $O(\sqrt{N})$, Pollard's Rho discrete log cycle detection, Pohlig-Hellman algorithm for smooth group orders |
| 9 | **Integer Factorization Algorithms** | Trial division, Fermat's difference of squares, Pollard's $p-1$ (smooth factors), Brent's cycle-finding variant of Pollard's Rho |
| 10 | **Constraint Solving using Z3** | Transparent Z3 solver wrapper (BitVec, Int, Bool, constraints, satisfiability check, model extraction) with graceful fallback |
| 11 | **SAT / SMT Solving** | Pure-Python DPLL SAT solver with Unit Propagation and Pure Literal Elimination for cryptanalytic Boolean constraints |
| 12 | **Chinese Remainder Theorem** | Standard pairwise coprime CRT and Generalized Non-Coprime CRT handling $\gcd(m_i, m_j) > 1$ with consistency validation |
| 13 | **Gaussian Elimination** | Bit-vector XOR row reduction over $\mathbb{F}_2$, linear system solver over $\mathbb{F}_p$, and exact rational solver over $\mathbb{Q}$ |
| 14 | **Hensel Lifting** | $p$-adic root lifting: lifts simple modular roots $f(r_0) \equiv 0 \pmod p$ to $r_k \equiv r_{k-1} - f(r_{k-1}) [f'(r_0)]^{-1} \pmod{p^k}$ |
| 15 | **Berlekamp–Massey Algorithm** | Generalized Berlekamp–Massey algorithm computing the minimal connection polynomial over arbitrary finite fields $\mathbb{F}_p$ |
| 16 | **LFSR Analysis** | Connection polynomial recovery, state evolution, cycle period computation, and keystream bit synthesis |
| 17 | **PRNG State Recovery** | LCG multiplier $a$ and increment $c$ recovery (known $m$), unknown modulus $m$ deduction via determinant GCDs, truncated LCG |
| 18 | **Mersenne Twister State Reconstruction** | MT19937 32-bit and 64-bit untempering, full 624-word state recovery from observed outputs, and standard Python `random.Random` cloning |

---

### L. Hash Cryptanalysis Suite (`hash_cryptanalysis.py`)

Automated hash identification, wordlist recovery, precomputed lookup caching, and collision cryptanalysis:

- **Hash Type Identification**: Distinguishes MD5 (32 hex), SHA-1 (40 hex), SHA-224 (56 hex), SHA-256 (64 hex), SHA-384 (96 hex), SHA-512 (128 hex), SHA-3 variants, and NTLM hashes.
- **Fast Precomputed Cache & Dictionary Cracking**: Instantaneous $O(1)$ lookup cache across MD5, SHA-1, and SHA-256 for common passwords, plus an expanded 50+ CTF keyword wordlist with salt support (`salted_hash_attack` supporting prefix and suffix placements).
- **Length Extension Attack (Merkle-Damgård)**: Automatically computes correct padding ($\text{data} \parallel \text{0x80} \parallel \text{0x00}^* \parallel \text{bit\_length}$) and forges authenticated messages for MD5, SHA-1, SHA-256, and SHA-512 without secret knowledge.
- **Birthday Collision Analysis**: Demonstrates truncated hash collisions in $O(2^{n/2})$ complexity using cycle-finding techniques.
- **External Cracker Integration**: Generates ready-to-run Hashcat (`hashcat -m <mode> -a 0 ...`) and John the Ripper (`john --format=<format> ...`) commands with accurate mode mappings.

---

### M. Autonomous Attack Strategy Selector (`attack_selector.py`)

Intelligent parameter extraction and heuristic attack hypothesis prioritization:

- **Autonomous Parameter Extraction**: Scans challenge text, scripts, and logs to extract mathematical parameters ($N, e, c, p, q, \phi, d, G_x, G_y, Q_x, Q_y, r, s, z, \text{IV}, \text{nonce}, \text{tag}$) with bit-length profiling.
- **Ciphertext Characterization**: Calculates Shannon entropy ($H = -\sum p_i \log_2 p_i$), printable character density, hex and base-encoding indicators to characterize ciphertext randomness.
- **Attack Hypothesis Ranking**: Evaluates candidates based on probability and computational cost ($O(1), O(\text{poly}), O(\text{subexp}), O(\text{exp})$), automatically prioritizing low-cost, high-probability vectors.

---

### N. Plaintext & Flag Verification Engine (`verification_engine.py`)

Multi-criteria sanity checking, flag extraction, dynamic prompt regex detection, and automated CTF writeup exportation:

- **Configurable & Dynamic CTF Flag Regexes**: Supports standard formats (`flag{...}`, `CTF{...}`, `picoCTF{...}`, `HTB{...}`, `THM{...}`) and dynamically parses custom flag prefixes directly from challenge prompts (`extract_custom_flag_patterns_from_prompt`).
- **Plaintext Sanity Validation**: Verifies printable ASCII ratios ($\ge 85\%$), reasonable Shannon entropy ($3.0 \le H \le 5.2$), vowel/consonant linguistic ratios, and English quadgram scores.
- **Mathematical Round-Trip Verification**: Validates RSA round-trip consistency ($c \equiv m^e \pmod N \iff m \equiv c^d \pmod N$) and ECC public key scalar multiplication ($Q = d \cdot P$).
- **10-Point CTF Solution Report**: Synthesizes a comprehensive writeup covering:
  1. Challenge Name
  2. Cryptographic Category
  3. Identified Vulnerability
  4. Extracted Mathematical Parameters
  5. Mathematical Vulnerability Model
  6. Attack Strategy & Algorithmic Complexity
  7. Standalone Python / SageMath Exploit Script
  8. Verified Plaintext / Recovered Flag
  9. Verification Proof
  10. Lessons Learned & Remediation
- **Automated CTF Writeup Exporter (`export_ctf_writeup`)**: Exports ready-to-publish GitHub-Flavored Markdown reports to `outputs/writeup.md` with attack matrices, reproduction scripts, and verification proofs.

---

### O. Custom Bitwise & Z3 Symbolic Reverser (`z3_symbolic_solver.py`)

Pure-Python symbolic execution AST and Z3 SMT solver for reversing non-standard CTF byte scramblers and custom Feistel ciphers:

- **PureBitVec AST Engine**: Lightweight symbolic expression tree (`PureBitVec`, `PureOpNode`) supporting bitwise AND, OR, XOR, NOT, left/right shifts, and modular arithmetic without requiring external native binaries.
- **Byte Transform Preimage Inversion (`solve_byte_transform_preimage`)**: Automatically recovers preimages for any deterministic $f(b) \to c$ byte scrambler via complete 256-state precomputation table.
- **Indexed Byte Transform Inversion (`solve_indexed_byte_transform_preimage`)**: Inverts position-dependent scramblers $f(i, b) \to c$ with key schedule/rotation dependencies.
- **$\mathbb{F}_2$ Linear System Solver (`solve_gf2_linear_system`)**: Solves arbitrary binary linear systems $A \cdot x \equiv b \pmod 2$ using Gaussian elimination over Galois field $\text{GF}(2)$.
- **Symbolic Z3 Bitwise Inversion (`z3_solve_bitwise_formula`)**: Expresses complex multi-round bit manipulation pipelines in Z3 SMT logic and extracts the satisfying input assignment.
- **Custom Feistel Network Reversal (`z3_solve_custom_feistel`)**: Reverses symmetric round functions $R_{i+1} = L_i \oplus F(R_i, K_i)$ for non-standard CTF challenges.
- **Autonomous Custom Cipher Solver (`analyze_and_solve_custom_cipher`)**: Detects Python encryption source code or bitwise expressions and automatically recovers plaintexts.

---

### P. Autonomous Interactive Socket Oracle Engine (`interactive_oracle_engine.py`)

Interactive client automation for live remote CTF network services:

- **InteractiveServiceSession**: Dynamic TCP session manager featuring automatic banner extraction, CLI menu parsing, regex-guided query/response dispatch, and socket timeout resilience.
- **Padding Oracle Adapter (`create_padding_oracle`)**: Wraps interactive network endpoints into high-speed local callable oracles for byte-at-a-time CBC decryption.
- **RSA Parity Oracle Adapter (`create_rsa_parity_oracle`)**: Adapts remote LSB / parity leak servers into binary search oracles for arbitrary modulus RSA plaintext recovery.
- **Autonomous Probe & Solve (`probe_and_solve_remote_service`)**: Connects to `host:port`, classifies service type, extracts public parameters, and runs targeted exploits against remote challenges.

---

### Q. 18-Discipline Verification & Benchmark Suite (`eval_benchmark.py`)

Automated validation suite evaluating correctness across 18 core cryptanalysis and bug bounty disciplines:

- **Test Disciplines**: RSA Cube Root, RSA Fermat, RSA Wiener, ECC BSGS DLog, Curve25519 Scalar Mult, Symmetric CBC Bit-Flip, Classical Vigenère, Classical Single-Byte XOR, Hash MD5 Cracking, Hash MD Length Extension, PRNG MT19937 Untwisting, PRNG LCG State Recovery, Lattice Clos Knapsack, Z3 / Bitwise Custom Inversion, Dynamic Flag Extraction, Recursive Multi-Layer Decoding, Bug Bounty Scope Gate Enforcement, Bug Bounty JWT & 10-Point Report.
- **Benchmark Performance**: **18 / 18 Disciplines Passed (100.0%)** in **0.39 seconds**.
- **Automated Logging**: Saves full test metrics and execution latencies to `outputs/benchmark_results.json`.

---

### R. Crypto Bug Bounty Assistant (`bug_bounty_crypto.py` & `AGENTS.md`)

An operational framework and live artifact auditor adhering to responsible disclosure standards for bug bounty engagements:

- **Mandatory 3-Factor Scope Gatekeeper (`ScopeGatekeeper`)**:
  - Automatically permits local files and CTF sandboxes (`inputs/...`, `127.0.0.1`, loopback).
  - Strictly enforces the 3 hard gates from `AGENTS.md` before analyzing any remote host:
    1. Verified program name (e.g. HackerOne / Bugcrowd listing)
    2. Verified program scope URL
    3. Explicit quote of the in-scope asset line matching the target domain/IP/API
  - Blocks prohibited actions (volumetric probing, DoS, brute forcing production auth).
- **JWT Security Auditor (`JWTAuditor`)**:
  - Detects `alg:none` / `None` / `NONE` bypasses and generates non-destructive test tokens.
  - Detects `RS256` to `HS256` public key confusion vulnerabilities and creates test vectors.
  - Identifies blank secrets (`secret = ""`) and instantly cracks weak HMAC secrets against common CTF and bounty dictionaries.
  - Checks for header injection risks: embedded `jwk`, untrusted `jku`/`x5u` URLs, and `kid` directory traversal sequences (`../../dev/null`).
  - Audits expiration timestamps (`exp`, `nbf`) and missing expiration claims.
- **Session & Reset Token PRNG Auditor (`SessionTokenAuditor`)**:
  - Measures token Shannon entropy and detects sequential counter increments.
  - Identifies embedded Unix timestamps (hex or decimal epoch time) and UUIDv1 time-based leakage.
  - Detects Mersenne Twister (MT19937) state leakage when consecutive tokens share 28+ of 32 bits from `time.time()` seeds.
- **Ciphertext Smell Auditor (`CiphertextSmellAuditor`)**:
  - Electronic Codebook (ECB) pattern leakage: flags duplicate 16-byte blocks within or across cookies/payloads.
  - CBC static or all-zero IV detection: reveals whether distinct ciphertexts share identical IVs.
  - AES-GCM nonce reuse: detects repeated 12-byte IVs, which catastrophically breaks integrity and exposes the GHASH key.
- **TLS / SSL Certificate Auditor (`TLSCertificateAuditor`)**:
  - Audits RSA key sizes (< 2048 bits), small exponents ($e=3$), and broken signature algorithms (MD5, SHA-1).
  - Performs non-destructive checks for the ROCA (CVE-2017-15361) Infineon prime structure.
- **10-Point Bug Bounty Responsible Disclosure Generator (`BugBountyReportGenerator`)**:
  - Synthesizes compliant reports matching the `AGENTS.md` format with Title, Affected Asset, CWE Mapping (CWE-347, CWE-326, CWE-330, CWE-329, CWE-328), Root Cause, Minimal Reproduction Steps, Redacted Evidence, Realistic Impact, Concrete Remediation Code, CVSS v3.1 Score & Vector String, and Disclosure Timeline SLA.

---

### 🌐 Web Dashboard & REST APIs (`app.py`)

The application features a modern Cyber/Glassmorphism web dashboard on `http://localhost:5000` with real-time SSE streaming logs:

- **12 Guided Category Selectors**: `Auto`, `RSA`, `Classical`, `XOR`, `AES`, `ECC`, `Lattice`, `PRNG`, `Hash`, `Encoding`, `Binary`, `Custom`
- **Multi-File & Multi-Format Upload Section**: Drag-and-drop or select multiple files simultaneously across diverse formats (Python/Sage scripts, PEM/DER keys, encrypted binaries, images/stego, packet captures, structured data) with format badges and individual file removal
- **85+ Interactive Attack Strategy Chips**: Guide the agent or test specific vulnerabilities directly across 18 Math Disciplines, Hash Cryptanalysis, PRNG, Lattice, Stego, Netcat, Symmetric, ECC, RSA, Classical, Block ciphers, and XOR
- **Remote Netcat Socket Input**: Connect directly to remote CTF servers (`nc host port`)
- **Decoded Output Viewer**: Clean output panel with copy functionality for any plaintext, key, or flag format
- **10-Point Solution Report Panel**: Instant CTF solution report viewer with markdown rendering and one-click clipboard copying
- **Candidate Permutations Panel**: Visualizes all classical cipher decryptions ranked by English quadgram scoring
- **Multi-Layer Encoding & Hash Inspection Card**: Displays recursive peeling layers and hash identification candidates
- **Instant Public Link Sharing (`share_agent.py` / `share_agent.bat`)**: Generates an instant public HTTPS link via SSH tunneling to share your running agent with any teammate or collaborator globally without port forwarding.

#### Direct REST Endpoints

| Endpoint | Method | Payload / Parameters | Description |
|---|---|---|---|
| `/api/advanced_math` | `POST` | `{"text": "weights=... or x = a (mod m) ..."}` | Direct instant Advanced Mathematical cryptanalysis (18 disciplines: LLL, BKZ, CRT, Hensel, Gröbner, Tonelli-Shanks, SAT) |
| `/api/hash_crack` | `POST` | `{"hash": "5d41402abc4b2a76b9719d911017c592"}` | Instant hash identification, embedded dictionary cracking, and Hashcat/John command generation |
| `/api/attack_ranking` | `POST` | `{"challenge": "N = ... e = 3 c = ..."}` | Parameter extraction, Shannon entropy profiling, and prioritized attack ranking |
| `/api/verify` | `POST` | `{"text": "flag{...}"}` | Plaintext sanity validation (entropy, printable ratio) and configurable CTF flag extraction |
| `/api/symmetric` | `POST` | `{"text": "cipher=... mode=... ct=..."}` | Direct instant parameter parsing & Symmetric attack execution (10 methods, 6 ciphers) |
| `/api/ecc` | `POST` | `{"text": "p=... a=... b=..."}` | Direct instant parameter parsing & ECC attack execution (10 methods + LLL HNP + Curve25519/Ed25519) |
| `/api/rsa` | `POST` | `{"text": "N=... e=... c=..."}` | Direct instant parameter parsing & RSA attack execution (15 methods + LLL + Parity Oracle + Bleichenbacher) |
| `/api/classical` | `POST` | `{"text": "..."}` | Direct instant analysis & decryption of classical ciphers (18 methods) |
| `/api/prng` | `POST` | `{"text": "outputs=[...] m=..."}` | Direct instant PRNG state untwisting (MT19937), LCG solving, and LFSR Berlekamp-Massey |
| `/api/lattice` | `POST` | `{"text": "weights=[...] target=..."}` | Direct instant low-density knapsack / subset-sum solving via rational LLL reduction |
| `/api/stego` | `POST` | `{"path": "inputs/..."}` | Direct instant LSB plane extraction and trailing EOF payload carving |
| `/api/socket_probe` | `POST` | `{"target": "host:port"}` | Interactive probe of remote CTF TCP / Netcat socket service |
| `/api/symbolic_solve` | `POST` | `{"text": "def encrypt(p)..."}` | PureBitVec & Z3 symbolic bitwise inversion, custom Feistel reversal, and byte transform preimage solving |
| `/api/interactive_probe` | `POST` | `{"host": "...", "port": ...}` | Autonomous interactive remote netcat service prober and menu-driven oracle solver |
| `/api/benchmark` | `GET` / `POST` | — | Runs the 18-discipline cryptanalysis and bug bounty benchmark suite (returns JSON report) |
| `/api/export_writeup` | `POST` | `{"report": "..."}` | Exports structured GitHub-Flavored Markdown CTF writeup to `outputs/writeup.md` |
| `/api/bug_bounty/scope_check` | `POST` | `{"target": "...", "program_name": "...", "in_scope_line": "..."}` | Evaluates 3 mandatory scope gates before remote interaction (AGENTS.md) |
| `/api/bug_bounty/analyze_artifact` | `POST` | `{"artifact": "...", "artifact_type": "jwt|session_tokens|ciphertext|auto"}` | Audits live artifacts for JWT flaws, PRNG smells, ECB leakage, and generates 10-point writeup |
| `/api/bug_bounty/jwt_audit` | `POST` | `{"token": "...", "public_key_pem": "..."}` | Targeted JWT audit (alg:none, RS256/HS256 confusion, weak secret cracking) |
| `/api/bug_bounty/generate_report` | `POST` | `{"title": "...", "affected_asset": "...", "finding_type": "..."}` | Synthesizes a 10-point responsible disclosure bug bounty report with CVSS v3.1 & CWE |
| `/api/models` | `GET` | — | Returns active model, fallback models chain, and key rotation status |
| `/api/cleanup` | `POST` | — | Purges unwanted temporary files from `inputs/` and `outputs/` directories |
| `/solve` | `POST` | `FormData(challenge, category, attack, nc_target, challenge_files, csrf_token)` | Dispatches challenge, socket target & files to autonomous agent |
| `/stream/<job_id>` | `GET` | — | Server-Sent Events (SSE) live stream of logs and execution results |

#### 🛡️ 16-Point File Upload Security Architecture (`upload_security.py`)

The application enforces an enterprise-grade, defense-in-depth security layer mitigating all OWASP file upload risks:

| # | Vulnerability | Security Risk | Implemented Protection & Patch |
|---|---|---|---|
| 1 | **Unrestricted File Upload** | Attacker uploads malicious files (scripts, executables) | Strict extension allowlist (`ALLOWED_EXTENSIONS`); blocks all executable formats |
| 2 | **Extension Bypass** | Multi-extension bypass (`.php.jpg`, `.exe`, `.phtml`, null bytes) | Multi-segment dot token parsing, null-byte rejection, and strict character sanitization |
| 3 | **MIME Type Spoofing** | Modified `Content-Type` header to disguise malicious files | Deep magic-byte inspection (validates true binary signatures; rejects PE/ELF disguised as images/text) |
| 4 | **Path Traversal** | Filenames like `../../etc/passwd` to escape directories | Strips traversal sequences, resolves paths strictly inside target directory, and prefixes filenames with UUIDs |
| 5 | **Remote Code Execution (RCE)** | Uploaded scripts or binaries executed on server host | Stored outside webroot in `inputs/`, execution bits stripped (`0o600`), runs strictly in isolated sandbox (`sandbox.py`) |
| 6 | **Malicious SVG Files** | SVG containing JavaScript, `<foreignObject>`, or XXE payloads | SVG uploads disabled; raw XML script and entity constructs blocked |
| 7 | **Zip Bomb** | Compressed archive expanding to gigabytes/terabytes | Strict limits: 10MB compressed max, 50MB uncompressed max, 10:1 max compression ratio, 100 entries max |
| 8 | **DoS via Large Files** | Upload flooding consuming RAM, disk, or bandwidth | 16MB max payload size (`MAX_CONTENT_LENGTH`), 10MB per file limit, 10 files max quota, IP rate limiting (30 req/min) |
| 9 | **Polyglot Files** | File valid in multiple formats (e.g. JPEG + PHP web shell) | Deep signature scanning for embedded PHP, JSP, HTML script tags, and image structure verification with Pillow |
| 10 | **Malware Upload** | Uploaded files containing web shells or reverse shells | Signature pattern scanner against known web shells (`eval(base64_decode`, `system($_GET`, `c99sh`, `r57shell`, etc.) |
| 11 | **Insecure File Permissions** | Uploads readable/writable by unauthorized system users | Filesystem permissions strictly clamped to `0o600` (owner read/write only, no world/group permissions) |
| 12 | **IDOR (Insecure Direct Object Reference)** | Users accessing or overwriting another user's uploads | Job/session directory isolation (`inputs/<job_id>/`); each execution is compartmentalized and unguessable |
| 13 | **Stored XSS** | Uploaded HTML or malicious documents executing in browser | Security response headers enforced: `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `X-Frame-Options: DENY` |
| 14 | **CSRF** | Unauthorized requests triggering uploads via victim session | Cryptographic HMAC-based CSRF tokens validated on all state-changing endpoints, plus Origin/Referer verification |
| 15 | **Race Conditions** | File accessed before validation completes (TOCTOU) | Atomic upload workflow: writes to quarantine `.tmp` file, runs validations, then performs atomic `os.replace` |
| 16 | **Information Disclosure** | Filenames, metadata, or paths leaking sensitive data | Strips EXIF/GPS/device metadata from images via Pillow; redacts absolute server paths in all responses and logs |

---

## 🧠 GRPO Fine-Tuning Pipeline

The model is trained using **Group Relative Policy Optimization (GRPO)** — a reinforcement learning algorithm that ranks a group of candidate outputs without needing a separate critic model.

```
  crypto_dataset.jsonl  (300 verified challenges)
           │
           ▼
  prepare_llama3_dataset()
  Format as Llama-3 chat prompts
           │
           ▼
  ┌──────────────────────────────────┐
  │  GRPOTrainer                     │
  │  Llama-3.1-8B + LoRA (r=16)      │
  │  4 candidate exploits / challenge│
  └──────────────┬───────────────────┘
                 │  for each candidate
                 ▼
  docker_crypto_reward_func()
  ┌────────────────────────────────┐
  │  Run in Docker sandbox         │
  │  +1.0  → exact flag match      │
  │  +0.2  → valid execution       │
  │   0.0  → crash / empty output  │
  └────────────────────────────────┘
                 │
                 ▼
  llama3-crypto-grpo-final/   (saved LoRA adapter)
```

**Why GRPO?**
- No need for human preference labels
- The Docker sandbox is an **objective, automated verifier**
- Multiple candidates per challenge allow relative ranking without a reward model

**LoRA Config:** rank=16, alpha=32, all attention and MLP projection layers, dropout=0.05

---

## 📁 Repository Structure

```
crypto-ctf-agent/
├── agent.py              # LangGraph state machine — core reasoning loop
├── llm_manager.py        # Automated Model & API Key Fallback Engine
├── solve.py              # CLI entry point: reads inputs/, launches agent
├── ecc_cryptanalysis.py  # ECC cryptanalysis suite (10 attacks & LLL HNP)
├── symmetric_cryptanalysis.py # Symmetric cryptanalysis suite (10 attacks, 6 ciphers)
├── classical_crypto.py   # Classical cryptanalysis suite (18 methods & solvers)
├── rsa_cryptanalysis.py  # RSA cryptanalysis suite (15 attacks & LLL lattice)
├── prng_cryptanalysis.py # PRNG & LFSR cryptanalysis (MT19937, LCG, LFSR Berlekamp-Massey)
├── lattice_crypto.py     # Rational LLL lattice reduction, Clos-Chor-Lemke knapsack & CVP
├── crypto_stego.py       # LSB plane extraction, trailing data & embedded archive carving
├── remote_socket_bridge.py # Live Netcat TCP socket client & oracle automation
├── ctf_knowledge_base.py # Curated exploit recipes & dynamic RAG guidance retrieval
├── advanced_math_crypto.py # Advanced mathematical cryptanalysis (18 disciplines: LLL, BKZ, CRT, Gröbner, Hensel, SAT)
├── hash_decoder.py       # Multi-layer hash & encoding auto-detector
├── z3_symbolic_solver.py # PureBitVec & Z3 symbolic bitwise solver, Feistel & byte preimage reverser
├── interactive_oracle_engine.py # Interactive TCP netcat oracle runner & menu-driven exploit adapter
├── bug_bounty_crypto.py  # Bug bounty live artifact auditor, scope gatekeeper & 10-point writer
├── AGENTS.md             # Bug bounty operating methodology, scope rules & report spec
├── eval_benchmark.py     # 18-discipline cryptanalysis & bug bounty benchmark suite (100% pass)
├── app.py                # Web dashboard & real-time SSE streaming solver
├── share_agent.py        # One-click instant public HTTPS link generator
├── share_agent.bat       # Windows launcher for instant public sharing
├── upload_security.py    # 16-point defense-in-depth file upload security manager
├── sandbox.py            # Docker execution engine with native fallback
├── data_generator.py     # Synthetic challenge factory (RSA, XOR, Classical, Binary)
├── train_llama3_grpo.py  # GRPO RL fine-tuning pipeline with Docker rewards
├── scratch_solve.py      # Quick one-off LLM query script (Groq/OpenAI compatible)
├── search_ctf.py         # (Utility) CTF challenge search helper
├── Dockerfile            # SageMath + gmpy2 + pwntools + z3 + pycryptodome sandbox image
├── requirements.txt      # Host Python dependencies
├── .env.example          # LLM backend configuration template
├── inputs/
│   └── prompt.txt        # Drop your challenge here
└── outputs/
    ├── exploit.py        # Last generated exploit script
    ├── result.txt        # Recovered plaintext / decoded result
    └── flag.txt          # Extracted flag format (if present)
```

---

## 🚀 Quickstart

### Prerequisites
- Python 3.10+
- Docker (recommended) or a local Python environment with gmpy2 + pycryptodome
- A running LLM endpoint: **Groq Cloud**, **Ollama**, **vLLM**, or **LM Studio**

---

### 1. Clone & Install

```bash
git clone https://github.com/Femiinnn/Autonomous-AI-Powered-Cryptography-CTF-Agent.git
cd Autonomous-AI-Powered-Cryptography-CTF-Agent
pip install -r requirements.txt
```

---

### 2. Configure the LLM Backend & Automated Fallbacks

Copy `.env.example` to `.env` and fill in your primary and fallback models:

```bash
cp .env.example .env
```

```env
# Groq Cloud Configuration
LLAMA3_API_BASE=https://api.groq.com/openai/v1
LLAMA3_API_KEY=gsk_your_primary_key_here
LLAMA3_MODEL_NAME=openai/gpt-oss-120b

# Automated Model Fallbacks (rotates when quota/rate-limits hit)
FALLBACK_MODELS=qwen/qwen3.8-27b,openai/gpt-oss-20b,allam-2-7b

# Automated API Key Rotation (rotates when an API key is exhausted)
FALLBACK_API_KEYS=gsk_second_key_here,gsk_third_key_here
```

---

### 3. Build the Docker Sandbox

```bash
docker build -t crypto-sandbox:latest .
```

> If Docker is unavailable, the sandbox automatically falls back to native Python/SageMath execution.

---

### 4. Solve a Challenge

**Option A — Launch the Web Dashboard (Recommended):**
```bash
python app.py
# Open http://localhost:5000 for the real-time cryptanalysis UI with live streaming logs
```

**Option B — CLI Execution (File input):**
```bash
echo "RSA Challenge:\nN = 1234...\ne = 56789...\nc = 9876...\nRecover the flag." > inputs/prompt.txt
python solve.py
```

**Option C — CLI Argument:**
```bash
python solve.py "RSA Challenge: N=... e=... c=... Recover the flag."
```

**Option D — Standalone Cryptanalysis Suites:**
```bash
# Run standalone RSA Cryptanalysis & LLL Engine
python rsa_cryptanalysis.py

# Run standalone Classical Cryptanalysis Suite
python classical_crypto.py
```

**Option E — Direct REST API:**
```bash
# Classical cipher solver
curl -X POST http://localhost:5000/api/classical -H "Content-Type: application/json" -d "{\"text\": \"Khoor Zruog\"}"

# RSA parameter analyzer
curl -X POST http://localhost:5000/api/rsa -H "Content-Type: application/json" -d "{\"text\": \"N = 899\ne = 11\nc = 40\"}"
```

Results and recovered plaintexts are saved to `outputs/result.txt`, `outputs/flag.txt`, and `outputs/exploit.py`.

---

### 5. Generate Training Dataset

```bash
python data_generator.py
# → crypto_dataset.jsonl (Verified challenges across RSA, Classical, XOR, and Binary)
```

---

### 6. Run GRPO Fine-Tuning *(GPU required)*

```bash
# Start your Llama-3 vLLM server or use HuggingFace Hub
python train_llama3_grpo.py
# → llama3-crypto-grpo-final/   (trained LoRA adapter)
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Agent Framework | [LangGraph](https://github.com/langchain-ai/langgraph) |
| LLM | [Meta Llama-3.1-8B-Instruct](https://llama.meta.com/) |
| LLM Serving | Ollama / vLLM / LM Studio / Groq |
| Code Execution | Docker (SageMath + Python 3) |
| Cryptographic Libraries | `gmpy2`, `pycryptodome`, `sympy`, `z3-solver`, `pwntools` |
| RL Training | [TRL GRPO](https://huggingface.co/docs/trl/grpo_trainer) |
| Fine-Tuning Method | [LoRA via PEFT](https://github.com/huggingface/peft) |
| Data Format | JSONL with verified ground-truth flags |

---

## 📊 How the Dataset is Generated

`data_generator.py` creates **mathematically verified** RSA challenges where the ground-truth flag is embedded in the ciphertext before generation — guaranteeing every sample is solvable:

```
flag = "flag{wiener_d_42_7391}"
m = bytes_to_long(flag.encode())         # plaintext integer
c = pow(m, e, n)                         # encrypt with vulnerable key
challenge = { problem: "N=..., e=..., c=..." , ground_truth_flag: flag }
```

Three attack classes × 100 samples = **300 total challenges** per dataset.

---

## 🤝 Contributing

Pull requests are welcome! Ideas for contribution:

- Add new challenge generators (AES-ECB, CBC Padding Oracle, ECC Pohlig-Hellman, PRNG reseeding)
- Build an `eval.py` harness to benchmark solve rate per attack type
- Add CTFtime/CTFd API integration to fetch real live challenges
- Improve the GRPO reward with partial-credit substring matching

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
