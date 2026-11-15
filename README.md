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

### 🛡️ RSA Cryptanalysis Suite (`rsa_cryptanalysis.py`)

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

### 🏛️ Classical Cryptanalysis Suite (`classical_crypto.py`)
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

---

### 🌐 Web Dashboard & REST APIs (`app.py`)

The application features a modern Cyber/Glassmorphism web dashboard on `http://localhost:5000` with real-time SSE streaming logs:

- **12 Guided Category Selectors**: `Auto`, `RSA`, `Classical`, `XOR`, `AES`, `ECC`, `Lattice`, `PRNG`, `Hash`, `Encoding`, `Binary`, `Custom`
- **Multi-File & Multi-Format Upload Section**: Drag-and-drop or select multiple files simultaneously across diverse formats (Python/Sage scripts, PEM/DER keys, encrypted binaries, images/stego, packet captures, structured data) with format badges and individual file removal
- **30+ Interactive Attack Strategy Chips**: Guide the agent or test specific vulnerabilities directly
- **Decoded Output Viewer**: Clean output panel with copy functionality for any plaintext, key, or flag format
- **Candidate Permutations Panel**: Visualizes all classical cipher decryptions ranked by English quadgram scoring
- **Multi-Layer Encoding & Hash Inspection Card**: Displays recursive peeling layers and hash identification candidates

#### Direct REST Endpoints

| Endpoint | Method | Payload / Parameters | Description |
|---|---|---|---|
| `/api/classical` | `POST` | `{"text": "..."}` | Direct instant analysis & decryption of classical ciphers (18 methods) |
| `/api/rsa` | `POST` | `{"text": "N=... e=... c=..."}` | Direct instant parameter parsing & RSA attack execution |
| `/solve` | `POST` | `FormData(challenge, category, attack, challenge_files)` | Dispatches challenge & uploaded files to autonomous LangGraph agent |
| `/stream/<job_id>` | `GET` | — | Server-Sent Events (SSE) live stream of logs and execution results |

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
├── solve.py              # CLI entry point: reads inputs/, launches agent
├── classical_crypto.py   # Classical cryptanalysis suite (18 methods & solvers)
├── rsa_cryptanalysis.py  # RSA cryptanalysis suite (15 attacks & LLL lattice)
├── hash_decoder.py       # Multi-layer hash & encoding auto-detector
├── app.py                # Web dashboard & real-time SSE streaming solver
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
- A running Llama-3 endpoint: **Ollama**, **vLLM**, **LM Studio**, or **Groq Cloud**

---

### 1. Clone & Install

```bash
git clone https://github.com/Femiinnn/Autonomous-AI-Powered-Cryptography-CTF-Agent.git
cd Autonomous-AI-Powered-Cryptography-CTF-Agent
pip install -r requirements.txt
```

---

### 2. Configure the LLM Backend

Copy `.env.example` to `.env` and fill in your backend:

```bash
cp .env.example .env
```

```env
# Option A: Local Ollama
LLAMA3_API_BASE=http://localhost:11434/v1
LLAMA3_API_KEY=ollama
LLAMA3_MODEL_NAME=llama3.1:8b

# Option B: Local vLLM
LLAMA3_API_BASE=http://localhost:8000/v1
LLAMA3_API_KEY=EMPTY
LLAMA3_MODEL_NAME=meta-llama/Meta-Llama-3.1-8B-Instruct

# Option C: Groq Cloud (free tier available)
LLAMA3_API_BASE=https://api.groq.com/openai/v1
LLAMA3_API_KEY=gsk_your_groq_key_here
LLAMA3_MODEL_NAME=llama-3.1-8b-instant
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
