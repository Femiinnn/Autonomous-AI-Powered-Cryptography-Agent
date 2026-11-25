import os
import json
import time
import queue
import threading
import re
import secrets
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response, stream_with_context, make_response
from werkzeug.utils import secure_filename
from upload_security import (
    UploadSecurityManager,
    SecurityValidationError,
    ALLOWED_EXTENSIONS,
    DANGEROUS_EXTENSIONS,
    IMAGE_EXTENSIONS,
    MAX_FILE_SIZE,
    MAX_TOTAL_FILES
)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = Path(__file__).parent / 'inputs'
app.config['OUTPUTS_FOLDER'] = Path(__file__).parent / 'outputs'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max payload size (DoS defense)

# Centralized 16-point defense-in-depth upload security manager
upload_sec = UploadSecurityManager(app.config['UPLOAD_FOLDER'])

# In-memory job store: job_id -> Queue
_job_queues: dict[str, queue.Queue] = {}


# ── 13. Security Headers Middleware (Stored XSS, Sniffing, Frame Injection) ───
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none';"
    )
    return response


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    # 14. CSRF Protection: Generate/maintain session_id and cryptographic HMAC token
    session_id = request.cookies.get('session_id')
    if not session_id or len(session_id) < 16:
        session_id = secrets.token_hex(16)
    csrf_token = upload_sec.generate_csrf_token(session_id)

    resp = make_response(render_template('index.html', csrf_token=csrf_token))
    resp.set_cookie('session_id', session_id, httponly=True, samesite='Strict', secure=False)
    return resp


@app.route('/solve', methods=['POST'])
def solve():
    # 8. DoS via Rate Limiting: Check client IP request quota
    client_ip = request.remote_addr or '127.0.0.1'
    if not upload_sec.check_rate_limit(client_ip, max_requests=30, window_seconds=60):
        return jsonify({
            'error': 'Rate limit exceeded: Please wait before submitting more challenge requests.',
            'vulnerability': 'DoS via Large Files / Request Flooding'
        }), 429

    # 14. CSRF Protection: Verify token
    session_id = request.cookies.get('session_id', '')
    csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token', '')
    if session_id and not upload_sec.validate_csrf_token(csrf_token, session_id):
        origin = request.headers.get('Origin', '')
        if origin and request.host not in origin:
            return jsonify({
                'error': 'CSRF verification failed: Origin mismatch or invalid CSRF token.',
                'vulnerability': 'CSRF'
            }), 403

    challenge_text = request.form.get('challenge', '').strip()
    category       = request.form.get('category', 'auto').strip()
    attack         = request.form.get('attack', 'auto').strip()
    nc_target      = request.form.get('nc_target', '').strip()
    bounty_url     = request.form.get('bounty_url', '').strip()
    if nc_target:
        challenge_text = (challenge_text + f"\n[Remote Netcat Target: {nc_target}]").strip()
    if bounty_url:
        challenge_text = (challenge_text + f"\n[Bug Bounty Target URL: {bounty_url}]").strip()

    # ── Handle uploaded files with 16-point Defense-in-Depth Security ─────────
    files_list = request.files.getlist('challenge_files')
    if not files_list:
        files_list = request.files.getlist('challenge_file')

    # Filter out empty file input submissions
    valid_files = [f for f in files_list if f and f.filename]
    if len(valid_files) > MAX_TOTAL_FILES:
        return jsonify({
            'error': f"Upload file quota exceeded: Maximum {MAX_TOTAL_FILES} files allowed per request.",
            'vulnerability': 'DoS via Large Files'
        }), 400

    # 12. IDOR / Session Isolation: Generate unique job ID before saving files
    job_id = f"{int(time.time() * 1000)}_{secrets.token_hex(4)}"
    file_info_blocks = []
    uploaded_metas = []

    for uploaded in valid_files:
        try:
            # 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16: Full pipeline verification
            meta = upload_sec.process_and_save_upload(uploaded, job_id=job_id)
            uploaded_metas.append(meta)
        except SecurityValidationError as sve:
            # Clean up any partial files for this job immediately
            upload_sec.cleanup_job(job_id)
            return jsonify({
                'error': f"Security validation rejected '{uploaded.filename}': {sve.message}",
                'vulnerability': sve.vulnerability
            }), 400
        except Exception as exc:
            upload_sec.cleanup_job(job_id)
            return jsonify({
                'error': f"Failed to safely process '{uploaded.filename}': {str(exc)[:100]}",
                'vulnerability': 'File Processing Error'
            }), 400

        fname = meta['display_name']
        save_path = meta['path']

        # Handle Archive Unpacking (ZIP / TAR / GZ)
        target_files_to_process = [(fname, save_path, meta)]
        if meta.get('extension') in ('zip', 'tar', 'gz', 'tgz'):
            try:
                extracted_entries = upload_sec.extract_safe_archive(save_path, save_path.parent)
                if extracted_entries:
                    file_info_blocks.append(f"\n📦 [Archive Auto-Extracted] {fname}: {len(extracted_entries)} files extracted into job workspace.\n")
                    for entry in extracted_entries:
                        target_files_to_process.append((entry['display_name'], entry['path'], entry))
            except Exception as e:
                file_info_blocks.append(f"\n⚠️ Archive extraction note: {e}\n")

        for curr_fname, curr_path, curr_meta in target_files_to_process:
            if curr_meta.get('extension') in ('zip', 'tar', 'gz', 'tgz') and len(target_files_to_process) > 1:
                continue  # Skip raw archive binary dump if files were unpacked
            if curr_meta.get('is_image'):
                try:
                    from PIL import Image
                    with Image.open(curr_path) as img:
                        file_info_blocks.append(
                            f"\n--- Attached Image: {curr_fname} ---\n"
                            f"Format: {img.format} | Dimensions: {img.size} | Mode: {img.mode} (EXIF metadata stripped)\n"
                            f"Your solver can open it directly in the working directory using:\n"
                            f"    from PIL import Image\n"
                            f"    img = Image.open('{curr_fname}')\n"
                        )
                except Exception:
                    file_info_blocks.append(f"\n--- Attached Image: {curr_fname} (size: {curr_meta['size_bytes']} bytes) ---\n")
            else:
                try:
                    raw_bytes = curr_path.read_bytes()
                    printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in raw_bytes[:4000])
                    total = min(len(raw_bytes), 4000)
                    is_text = (printable / max(total, 1)) > 0.80

                    if is_text:
                        text_content = raw_bytes.decode('utf-8', errors='replace').strip()
                        if len(text_content) > 100000:
                            preview = text_content[:100000] + f"\n... [Truncated: showing 100KB of {len(raw_bytes)} bytes]"
                        else:
                            preview = text_content
                        file_info_blocks.append(
                            f"\n--- Attached File: {curr_fname} ({len(raw_bytes)} bytes) ---\n"
                            f"{preview}\n"
                        )
                    else:
                        hex_sample = raw_bytes[:128].hex()
                        file_info_blocks.append(
                            f"\n--- Attached Binary/Encrypted File: {curr_fname} ({len(raw_bytes)} bytes) ---\n"
                            f"First {min(len(raw_bytes), 128)} bytes (hex): {hex_sample}\n"
                            f"The file is accessible in your solver working directory as '{curr_fname}'. Read with:\n"
                            f"    with open('{curr_fname}', 'rb') as f:\n"
                            f"        data = f.read()\n"
                        )
                except Exception:
                    file_info_blocks.append(f"\n--- Attached File: {curr_fname} ({curr_meta.get('size_bytes', 0)} bytes) ---\n")

    # Merge text + file content
    full_challenge = challenge_text
    if file_info_blocks:
        full_challenge = (full_challenge + '\n' + '\n'.join(file_info_blocks)).strip()

    if not full_challenge:
        upload_sec.cleanup_job(job_id)
        return jsonify({'error': 'Please provide a challenge description or upload a file.'}), 400

    # Inject user-selected hints so the agent respects them
    hints = []
    if category and category.lower() not in ('auto', ''):
        hints.append(f"[Category Hint: {category}]")
    if attack and attack.lower() not in ('auto', ''):
        hints.append(f"[Attack Hint: {attack}]")
    if hints:
        full_challenge = '\n'.join(hints) + '\n' + full_challenge

    # ── Spawn background agent thread ─────────────────────────────────────────
    q: queue.Queue = queue.Queue()
    _job_queues[job_id] = q

    def run_agent():
        import sys

        class _QWriter:
            def write(self, text):
                stripped = text.strip()
                if stripped:
                    q.put({'type': 'log', 'message': stripped})
            def flush(self):
                pass

        old_stdout = sys.stdout
        sys.stdout = _QWriter()
        try:
            from agent import crypto_solver_agent
            result = crypto_solver_agent.invoke({'challenge': full_challenge, 'job_id': job_id})
            flag = result.get('captured_flag')
            code = result.get('generated_code', '')
            stdout_out = result.get('execution_stdout', '')
            # ── Hash / Encoding analysis ────────────────────────────────────
            ha = result.get('hash_analysis') or {}
            full_ha = ha.get('full') or {}
            hash_info = {
                'summary':          full_ha.get('summary', ''),
                'is_double_encoded':full_ha.get('is_double_encoded', False),
                'total_layers':     full_ha.get('total_layers', 0),
                'final_decoded':    full_ha.get('final_decoded', ''),
                'layers': [
                    {
                        'layer':     l.get('layer', 0),
                        'type':      l.get('type', ''),
                        'encoding':  l.get('encoding', ''),
                        'decoded':   l.get('decoded', ''),
                        'is_hash':   l.get('is_hash', False),
                        'hash_algos':[a.get('algorithm','') for a in (l.get('hash_algorithms') or [])],
                        'confidence':l.get('confidence', ''),
                    }
                    for l in (full_ha.get('encoding_layers') or [])
                ],
                'substrings': [
                    {
                        'original': s.get('original', ''),
                        'summary':  s.get('summary', ''),
                        'final_decoded': s.get('final_decoded', ''),
                        'is_double_encoded': s.get('is_double_encoded', False),
                        'encoding': (s.get('encoding_layers') or [{}])[0].get('encoding', ''),
                    }
                    for s in (ha.get('substrings') or [])
                ]
            }

            # ── Classical Cryptanalysis analysis ─────────────────────────────
            ca = result.get('classical_analysis') or {}
            classical_info = {
                'index_of_coincidence': ca.get('index_of_coincidence', 0),
                'chi_squared': ca.get('chi_squared', 0),
                'most_common_letters': ca.get('most_common_letters', []),
                'top_match': ca.get('top_match', {}),
                'decoded_result': ca.get('decoded_result', ''),
                'all_decoded_results': ca.get('all_decoded_results', []),
                'ranked_candidates': ca.get('ranked_candidates', [])
            }

            # Genuine decoded result from agent execution
            decoded_result = result.get('decoded_result') or result.get('captured_flag')

            # Fallback to script stdout if not already set
            if not decoded_result and stdout_out.strip():
                lines = [line.strip() for line in stdout_out.strip().splitlines() if line.strip()]
                if lines:
                    cand = lines[-1] if len(lines) > 1 and ("error" not in lines[-1].lower()) else "\n".join(lines)
                    decoded_result = cand

            # STRICT CHECK: Never treat the raw challenge input as the decoded result!
            if decoded_result and decoded_result.strip() == full_challenge.strip():
                decoded_result = None

            # ── RSA Analysis ─────────────────────────────────────────────────
            ra = result.get('rsa_analysis') or {}
            rsa_info = {
                'status': ra.get('status', ''),
                'attack': ra.get('attack', ''),
                'flag': ra.get('flag', '')
            }

            # ── ECC Analysis ─────────────────────────────────────────────────
            ea = result.get('ecc_analysis') or {}
            ecc_info = {
                'status': ea.get('status', ''),
                'attack': ea.get('attack', ''),
                'flag': ea.get('flag', ''),
                'explanation': ea.get('explanation', '')
            }

            # ── Symmetric Analysis ───────────────────────────────────────────
            sa = result.get('symmetric_analysis') or {}
            symmetric_info = {
                'status': sa.get('status', ''),
                'cipher': sa.get('cipher', ''),
                'mode': sa.get('mode', ''),
                'attack': sa.get('attack') or sa.get('method', ''),
                'flag': sa.get('flag', ''),
                'explanation': sa.get('explanation', '')
            }

            # ── PRNG Analysis ────────────────────────────────────────────────
            pa = result.get('prng_analysis') or {}
            prng_info = {
                'status': pa.get('status', ''),
                'generator': pa.get('generator', ''),
                'attack': pa.get('attack', ''),
                'flag': pa.get('flag', ''),
                'explanation': pa.get('explanation', '')
            }

            # ── Lattice Analysis ─────────────────────────────────────────────
            la = result.get('lattice_analysis') or {}
            lattice_info = {
                'status': la.get('status', ''),
                'cipher': la.get('cipher', ''),
                'attack': la.get('attack', ''),
                'flag': la.get('flag', ''),
                'density': la.get('density', 0),
                'explanation': la.get('explanation', '')
            }

            # ── Stego Analysis ───────────────────────────────────────────────
            sta = result.get('stego_analysis') or {}
            stego_info = {
                'status': sta.get('status', ''),
                'attack': sta.get('attack', ''),
                'flag': sta.get('flag', ''),
                'findings': sta.get('findings', [])
            }

            # ── Advanced Mathematical Analysis ───────────────────────────────
            ma = result.get('math_analysis') or {}
            math_info = {
                'status': ma.get('status', ''),
                'method': ma.get('method', ''),
                'flag': ma.get('flag', ''),
                'methods_checked': ma.get('methods_checked', [])
            }

            # ── Bug Bounty Analysis ──────────────────────────────────────────
            bba = result.get('bug_bounty_analysis') or {}
            bug_bounty_info = {
                'artifact_type': bba.get('artifact_type', ''),
                'result': bba.get('result', {})
            }

            q.put({
                'type': 'result',
                'decoded_result': decoded_result,
                'flag': decoded_result,
                'code': code,
                'stdout': stdout_out,
                'hash_info': hash_info,
                'classical_info': classical_info,
                'rsa_info': rsa_info,
                'ecc_info': ecc_info,
                'symmetric_info': symmetric_info,
                'prng_info': prng_info,
                'lattice_info': lattice_info,
                'stego_info': stego_info,
                'math_info': math_info,
                'bug_bounty_info': bug_bounty_info,
                'solution_report': result.get('solution_report', ''),
                'ranked_hypotheses': result.get('ranked_hypotheses', []),
                'extracted_parameters': result.get('extracted_parameters', {})
            })

            # Save clean final outputs to outputs/
            try:
                out_dir = app.config['OUTPUTS_FOLDER']
                out_dir.mkdir(exist_ok=True)
                if code:
                    (out_dir / 'exploit.py').write_text(code, encoding='utf-8')
                if decoded_result:
                    (out_dir / 'result.txt').write_text(str(decoded_result), encoding='utf-8')
                    (out_dir / 'flag.txt').write_text(str(decoded_result), encoding='utf-8')
                if result.get('solution_report'):
                    (out_dir / 'solution_report.txt').write_text(str(result['solution_report']), encoding='utf-8')
            except Exception:
                pass
        except Exception as exc:
            q.put({'type': 'error', 'message': str(exc)})
        finally:
            sys.stdout = old_stdout
            q.put({'type': 'done'})
            # ── Automatic cleanup: securely purge isolated job directory from inputs/
            upload_sec.cleanup_job(job_id)

    t = threading.Thread(target=run_agent, daemon=True)
    t.start()

    return jsonify({'job_id': job_id})


@app.route('/stream/<job_id>')
def stream(job_id: str):
    """Server-Sent Events endpoint — streams live logs and final result."""
    def generate():
        q = _job_queues.get(job_id)
        if not q:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Job not found'})}\n\n"
            return
        while True:
            try:
                msg = q.get(timeout=90)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get('type') in ('done', 'error'):
                    _job_queues.pop(job_id, None)
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/api/classical', methods=['POST'])
def api_classical():
    """Direct instant Classical Cryptanalysis API endpoint."""
    data = request.get_json(silent=True) or {}
    text = data.get('text', '') or request.form.get('text', '')
    if not text.strip():
        return jsonify({'error': 'Please provide text or ciphertext to analyze.'}), 400
    try:
        from classical_crypto import analyze_and_solve_classical
        res = analyze_and_solve_classical(text)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/rsa', methods=['POST'])
def api_rsa():
    """Direct instant RSA Cryptanalysis API endpoint."""
    data = request.get_json(silent=True) or {}
    text = data.get('text', '') or request.form.get('text', '')
    if not text.strip():
        return jsonify({'error': 'Please provide RSA parameters (N, e, c).'}), 400
    try:
        from rsa_cryptanalysis import analyze_and_solve_rsa
        res = analyze_and_solve_rsa(text)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ecc', methods=['POST'])
def api_ecc():
    """Direct instant Elliptic Curve Cryptanalysis (ECC) API endpoint."""
    data = request.get_json(silent=True) or {}
    text = data.get('text', '') or request.form.get('text', '')
    if not text.strip():
        return jsonify({'error': 'Please provide ECC parameters (p, a, b, G, Q, or ECDSA signatures).'}), 400
    try:
        from ecc_cryptanalysis import analyze_and_solve_ecc
        res = analyze_and_solve_ecc(text)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/symmetric', methods=['POST'])
def api_symmetric():
    """Direct instant Symmetric Cryptanalysis API endpoint."""
    data = request.get_json(silent=True) or {}
    text = data.get('text', '') or request.form.get('text', '')
    if not text.strip():
        return jsonify({'error': 'Please provide symmetric parameters (cipher, mode, key, iv, ciphertext, etc.).'}), 400
    try:
        from symmetric_cryptanalysis import analyze_and_solve_symmetric
        res = analyze_and_solve_symmetric(text)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/prng', methods=['POST'])
def api_prng():
    """Direct instant PRNG & LFSR Cryptanalysis API endpoint."""
    data = request.get_json(silent=True) or {}
    text = data.get('text', '') or request.form.get('text', '')
    if not text.strip():
        return jsonify({'error': 'Please provide PRNG or LFSR output sequences.'}), 400
    try:
        from prng_cryptanalysis import analyze_and_solve_prng
        res = analyze_and_solve_prng(text)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/lattice', methods=['POST'])
def api_lattice():
    """Direct instant Lattice Cryptanalysis (Subset Sum / Knapsack) API endpoint."""
    data = request.get_json(silent=True) or {}
    text = data.get('text', '') or request.form.get('text', '')
    if not text.strip():
        return jsonify({'error': 'Please provide knapsack weights and target sum.'}), 400
    try:
        from lattice_crypto import analyze_and_solve_lattice
        res = analyze_and_solve_lattice(text)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stego', methods=['POST'])
def api_stego():
    """Direct instant Steganography analysis API endpoint."""
    data = request.get_json(silent=True) or {}
    target_dir = data.get('path', '') or str(app.config['UPLOAD_FOLDER'])
    try:
        from crypto_stego import analyze_and_solve_stego
        res = analyze_and_solve_stego(target_dir)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/socket_probe', methods=['POST'])
def api_socket_probe():
    """Probe a remote netcat CTF socket service."""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '') or request.form.get('target', '')
    if not target.strip():
        return jsonify({'error': 'Please provide host:port or nc command.'}), 400
    try:
        from remote_socket_bridge import parse_nc_command, probe_remote_service
        host, port = parse_nc_command(target)
        res = probe_remote_service(host, port)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/advanced_math', methods=['POST'])
def api_advanced_math():
    """Direct instant Advanced Mathematical Cryptanalysis API endpoint."""
    data = request.get_json(silent=True) or {}
    text = data.get('text', '') or request.form.get('text', '')
    if not text.strip():
        return jsonify({'error': 'Please provide mathematical challenge parameters.'}), 400
    try:
        from advanced_math_crypto import analyze_and_solve_advanced_math
        res = analyze_and_solve_advanced_math(text)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/models', methods=['GET'])
def api_models():
    """Returns the currently active model and configured fallback chain."""
    try:
        from llm_manager import fallback_llm
        return jsonify(fallback_llm.get_status())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cleanup', methods=['POST'])
def api_cleanup():
    """
    Cleans up unwanted temporary files from inputs/ and outputs/ directories.
    Preserves default prompt.txt template if present.
    """
    cleaned = {'inputs': [], 'outputs': []}
    try:
        in_dir = app.config['UPLOAD_FOLDER']
        if in_dir.exists():
            for item in in_dir.iterdir():
                if item.name == 'prompt.txt':
                    continue
                try:
                    if item.is_file():
                        item.unlink()
                        cleaned['inputs'].append(item.name)
                    elif item.is_dir() and item.name != '.quarantine':
                        import shutil
                        shutil.rmtree(item, ignore_errors=True)
                        cleaned['inputs'].append(item.name)
                except Exception:
                    pass
        out_dir = app.config['OUTPUTS_FOLDER']
        if out_dir.exists():
            for item in out_dir.iterdir():
                if item.is_file():
                    try:
                        item.unlink()
                        cleaned['outputs'].append(item.name)
                    except Exception:
                        pass
        return jsonify({'status': 'ok', 'message': 'Unwanted files cleaned up successfully.', 'cleaned': cleaned})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/hash_crack', methods=['POST'])
def api_hash_crack():
    """Hash identification, dictionary cracking, and cracking tool command generation."""
    data = request.get_json(silent=True) or {}
    hex_hash = data.get('hash', '') or request.form.get('hash', '')
    if not hex_hash.strip():
        return jsonify({'error': 'Please provide a hash string.'}), 400
    try:
        from hash_cryptanalysis import identify_hash_type, dictionary_attack, generate_cracking_commands
        candidates = identify_hash_type(hex_hash.strip())
        crack_result = None
        if candidates:
            crack_result = dictionary_attack(hex_hash.strip(), candidates[0]['type'])
        commands = generate_cracking_commands(hex_hash.strip())
        return jsonify({
            'hash': hex_hash.strip(),
            'candidates': candidates,
            'crack_result': crack_result,
            'cracking_commands': commands
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/attack_ranking', methods=['POST'])
def api_attack_ranking():
    """Autonomous attack strategy ranking based on probability and cost."""
    data = request.get_json(silent=True) or {}
    text = data.get('challenge', '') or request.form.get('challenge', '')
    if not text.strip():
        return jsonify({'error': 'Please provide challenge text or ciphertext.'}), 400
    try:
        from attack_selector import extract_parameters, analyze_ciphertext_characteristics, rank_attack_strategies
        params = extract_parameters(text)
        charac = analyze_ciphertext_characteristics(text)
        ranked = rank_attack_strategies(params, charac, text)
        return jsonify({
            'extracted_parameters': params,
            'characteristics': charac,
            'ranked_hypotheses': ranked
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/verify', methods=['POST'])
def api_verify():
    """Plaintext sanity check and flag extraction endpoint."""
    data = request.get_json(silent=True) or {}
    candidate = data.get('text', '') or request.form.get('text', '')
    if not candidate.strip():
        return jsonify({'error': 'Please provide text to verify.'}), 400
    try:
        from verification_engine import extract_flag, validate_plaintext
        flag = extract_flag(candidate)
        val = validate_plaintext(candidate)
        return jsonify({
            'extracted_flag': flag,
            'validation': val
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/symbolic_solve', methods=['POST'])
def api_symbolic_solve():
    """Autonomous Z3 & Pure-Python symbolic bitwise reverser for custom ciphers."""
    data = request.get_json(silent=True) or {}
    text = data.get('challenge', '') or request.form.get('challenge', '')
    if not text.strip():
        return jsonify({'error': 'Please provide challenge text containing custom cipher code/ciphertext.'}), 400
    try:
        from z3_symbolic_solver import analyze_and_solve_custom_cipher
        res = analyze_and_solve_custom_cipher(text)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/interactive_probe', methods=['POST'])
def api_interactive_probe():
    """Probe and automate interactive netcat/TCP service oracles."""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '') or request.form.get('target', '')
    if not target.strip():
        return jsonify({'error': 'Please provide target host:port or nc command.'}), 400
    try:
        from interactive_oracle_engine import probe_and_solve_remote_service
        res = probe_and_solve_remote_service(target)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/benchmark', methods=['GET', 'POST'])
def api_benchmark():
    """Runs the 16-discipline cryptanalysis evaluation benchmark and returns summary."""
    try:
        from eval_benchmark import run_benchmark_suite
        res = run_benchmark_suite()
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export_writeup', methods=['POST'])
def api_export_writeup():
    """Exports structured CTF challenge writeup in Markdown."""
    data = request.get_json(silent=True) or {}
    report = data.get('report', '')
    title = data.get('title', 'CTF Cryptographic Challenge')
    if not report.strip():
        out_file = app.config['OUTPUTS_FOLDER'] / 'solution_report.txt'
        if out_file.exists():
            report = out_file.read_text(encoding='utf-8')
    try:
        from verification_engine import export_ctf_writeup
        md = export_ctf_writeup(report, challenge_name=title, output_file=str(app.config['OUTPUTS_FOLDER'] / 'writeup.md'))
        return jsonify({'status': 'ok', 'writeup_markdown': md, 'path': 'outputs/writeup.md'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Bug Bounty Cryptographic Endpoints (AGENTS.md) ──────────────────────────

@app.route('/api/bug_bounty/scope_check', methods=['POST'])
def api_bug_bounty_scope_check():
    """Enforces the 3 mandatory scope gates before touching any remote target."""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '')
    program_name = data.get('program_name', '')
    program_url = data.get('program_url', '')
    in_scope_line = data.get('in_scope_line', '')
    prohibited_actions = data.get('prohibited_actions', [])
    intended_action = data.get('intended_action', '')
    try:
        from bug_bounty_crypto import ScopeGatekeeper
        gate = ScopeGatekeeper.validate_scope(
            target=target,
            program_name=program_name,
            program_url=program_url,
            in_scope_line=in_scope_line,
            prohibited_actions=prohibited_actions,
            intended_action=intended_action
        )
        return jsonify({
            'allowed': gate.allowed,
            'target_type': gate.target_type,
            'reason': gate.reason,
            'warnings': gate.warnings,
            'missing_fields': gate.missing_fields
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/bug_bounty/analyze_artifact', methods=['POST'])
def api_bug_bounty_analyze_artifact():
    """Audits live artifacts (JWT, cookies, session tokens, ciphertexts, TLS certs)."""
    data = request.get_json(silent=True) or {}
    artifact = data.get('artifact', '')
    artifact_type = data.get('artifact_type', 'auto')
    endpoint = data.get('target_endpoint', 'https://target.com/api')
    if not artifact.strip():
        return jsonify({'error': 'No artifact provided'}), 400
    try:
        from bug_bounty_crypto import audit_bug_bounty_artifact
        res = audit_bug_bounty_artifact(artifact, artifact_type=artifact_type, target_endpoint=endpoint)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/bug_bounty/jwt_audit', methods=['POST'])
def api_bug_bounty_jwt_audit():
    """Detailed JWT security audit for alg:none, key confusion, and secret cracking."""
    data = request.get_json(silent=True) or {}
    token = data.get('token', '')
    public_key = data.get('public_key_pem', None)
    if not token.strip():
        return jsonify({'error': 'No JWT token provided'}), 400
    try:
        from bug_bounty_crypto import JWTAuditor
        res = JWTAuditor.audit_token(token, public_key_pem=public_key)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/bug_bounty/generate_report', methods=['POST'])
def api_bug_bounty_generate_report():
    """Generates a 10-point responsible disclosure bug bounty report in Markdown."""
    data = request.get_json(silent=True) or {}
    title = data.get('title', 'Cryptographic Implementation Vulnerability')
    affected_asset = data.get('affected_asset', 'https://target.com')
    finding_type = data.get('finding_type', 'ALG_NONE_ACTIVE')
    root_cause = data.get('root_cause', 'Cryptographic flaw detected.')
    reproduction_steps = data.get('reproduction_steps', ['Step 1: Inspect token', 'Step 2: Verify flaw'])
    evidence = data.get('evidence', '[REDACTED]')
    impact = data.get('impact', 'Potential authentication bypass.')
    suggested_fix = data.get('suggested_fix', 'Upgrade cryptographic libraries.')
    program_sla = data.get('program_sla', 'Standard 90-day responsible disclosure window')
    try:
        from bug_bounty_crypto import BugBountyReportGenerator
        rep = BugBountyReportGenerator.generate_report(
            title=title,
            affected_asset=affected_asset,
            finding_type=finding_type,
            root_cause=root_cause,
            reproduction_steps=reproduction_steps,
            evidence=evidence,
            impact=impact,
            suggested_fix=suggested_fix,
            program_sla=program_sla
        )
        return jsonify({'status': 'ok', 'report': rep})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/bug_bounty/audit_url', methods=['POST'])
def api_bug_bounty_audit_url():
    """Passively audits a live target URL for cryptographic and implementation flaws."""
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    program_name = data.get('program_name', '').strip()
    in_scope_line = data.get('in_scope_line', '').strip()
    program_url = data.get('program_url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    try:
        from bug_bounty_crypto import audit_target_url
        res = audit_target_url(
            target_url=url,
            program_name=program_name,
            in_scope_line=in_scope_line,
            program_url=program_url
        )
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export_poc', methods=['POST'])
def api_export_poc():
    """Generates and exports a 100% standalone zero-dependency Python exploit script (outputs/poc.py)."""
    data = request.get_json(silent=True) or {}
    code = data.get('code', '')
    params = data.get('parameters', {})
    flag = data.get('flag', '')
    cat = data.get('category', 'Cryptanalysis')
    vuln = data.get('vulnerability', 'Cryptographic Flaw')
    if not code.strip():
        exploit_file = app.config['OUTPUTS_FOLDER'] / 'exploit.py'
        if exploit_file.exists():
            code = exploit_file.read_text(encoding='utf-8')
    try:
        from poc_exporter import export_standalone_poc
        out_file = str(app.config['OUTPUTS_FOLDER'] / 'poc.py')
        script = export_standalone_poc(
            exploit_code=code,
            parameters=params,
            verified_flag=flag,
            category=cat,
            vulnerability=vuln,
            output_path=out_file
        )
        return jsonify({'status': 'ok', 'poc_code': script, 'path': 'outputs/poc.py'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/batch_solve', methods=['POST'])
def api_batch_solve():
    """Concurrently triages and solves multiple challenges in parallel."""
    data = request.get_json(silent=True) or {}
    challenges = data.get('challenges', [])
    workers = int(data.get('max_workers', 4))
    if not challenges:
        return jsonify({'error': 'No challenges provided for batch solving'}), 400
    try:
        from batch_solver import BatchSolver
        solver = BatchSolver(max_workers=min(workers, 8))
        res = solver.solve_batch(challenges)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/timing_audit', methods=['POST'])
def api_timing_audit():
    """Performs statistical Welch's t-test timing side-channel analysis."""
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No target URL provided'}), 400
    try:
        import urllib.request
        def url_oracle(candidate: str) -> bool:
            try:
                req = urllib.request.Request(
                    url,
                    data=candidate.encode(),
                    headers={'Content-Type': 'text/plain', 'User-Agent': 'CryptoAgent-TimingAuditor'}
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    return resp.status == 200
            except Exception:
                return False

        from timing_oracle import TimingOracleSolver
        res = TimingOracleSolver.audit_timing_leakage(url_oracle, sample_size=10, endpoint_url=url)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/federated_audit', methods=['POST'])
def api_federated_audit():
    """Audits OAuth 2.0 authorization URLs or SAML 2.0 XML responses."""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No OAuth URL or SAML XML provided'}), 400
    try:
        from oauth_saml_auditor import audit_federated_identity
        res = audit_federated_identity(target)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    app.run(host=host, port=port, debug=True, threaded=True)
