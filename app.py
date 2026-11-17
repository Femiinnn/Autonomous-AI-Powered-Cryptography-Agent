import os
import json
import time
import queue
import threading
import re
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = Path(__file__).parent / 'inputs'
app.config['OUTPUTS_FOLDER'] = Path(__file__).parent / 'outputs'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB

DISALLOWED_EXTENSIONS = {'exe', 'bat', 'cmd', 'vbs', 'msi', 'scr', 'com', 'ps1'}
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp', 'tiff', 'tif', 'svg', 'ico'}

# In-memory job store: job_id -> Queue
_job_queues: dict[str, queue.Queue] = {}


def allowed_file(filename: str) -> bool:
    if not filename or '.' not in filename:
        return True  # Files without extension are common in CTF (e.g. 'chall', 'output', 'secret')
    ext = filename.rsplit('.', 1)[1].lower()
    return ext not in DISALLOWED_EXTENSIONS


def is_image(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in IMAGE_EXTENSIONS


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/solve', methods=['POST'])
def solve():
    challenge_text = request.form.get('challenge', '').strip()
    category       = request.form.get('category', 'auto').strip()
    attack         = request.form.get('attack', 'auto').strip()

    # ── Handle uploaded files (multi-file & multi-format support) ────────────
    files_list = request.files.getlist('challenge_files')
    if not files_list:
        files_list = request.files.getlist('challenge_file')

    file_info_blocks = []
    app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
    app.config['OUTPUTS_FOLDER'].mkdir(exist_ok=True)
    uploaded_saved_paths = []

    for uploaded in files_list:
        if not uploaded or not uploaded.filename:
            continue
        fname = secure_filename(uploaded.filename)
        if not fname:
            fname = f"upload_{int(time.time() * 1000)}"
        if not allowed_file(fname):
            continue

        save_path = app.config['UPLOAD_FOLDER'] / fname
        uploaded.save(save_path)
        uploaded_saved_paths.append(save_path)

        if is_image(fname):
            try:
                from PIL import Image
                with Image.open(save_path) as img:
                    file_info_blocks.append(
                        f"\n--- Attached Image: {fname} ---\n"
                        f"Format: {img.format} | Dimensions: {img.size} | Mode: {img.mode}\n"
                        f"Your solver can open it directly in the working directory using:\n"
                        f"    from PIL import Image\n"
                        f"    img = Image.open('{fname}')\n"
                    )
            except Exception as e:
                file_info_blocks.append(f"\n--- Attached Image: {fname} (size: {save_path.stat().st_size} bytes) ---\n")
        else:
            try:
                raw_bytes = save_path.read_bytes()
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
                        f"\n--- Attached File: {fname} ({len(raw_bytes)} bytes) ---\n"
                        f"{preview}\n"
                    )
                else:
                    hex_sample = raw_bytes[:128].hex()
                    file_info_blocks.append(
                        f"\n--- Attached Binary/Encrypted File: {fname} ({len(raw_bytes)} bytes) ---\n"
                        f"First {min(len(raw_bytes), 128)} bytes (hex): {hex_sample}\n"
                        f"The file is accessible in your solver working directory as '{fname}'. Read with:\n"
                        f"    with open('{fname}', 'rb') as f:\n"
                        f"        data = f.read()\n"
                    )
            except Exception as e:
                file_info_blocks.append(f"\n--- Attached File: {fname} ({save_path.stat().st_size} bytes) ---\n")

    # Merge text + file content
    full_challenge = challenge_text
    if file_info_blocks:
        full_challenge = (full_challenge + '\n' + '\n'.join(file_info_blocks)).strip()

    if not full_challenge:
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
    job_id = f"{int(time.time() * 1000)}"
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
            result = crypto_solver_agent.invoke({'challenge': full_challenge})
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
                'symmetric_info': symmetric_info
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
            except Exception:
                pass
        except Exception as exc:
            q.put({'type': 'error', 'message': str(exc)})
        finally:
            sys.stdout = old_stdout
            q.put({'type': 'done'})
            # ── Automatic cleanup: remove uploaded challenge files from inputs/ after execution
            for p in uploaded_saved_paths:
                try:
                    if p.exists() and p.is_file():
                        p.unlink()
                except Exception:
                    pass

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
                if item.is_file() and item.name != 'prompt.txt':
                    try:
                        item.unlink()
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


if __name__ == '__main__':
    app.run(debug=True, port=5000, threaded=True)
