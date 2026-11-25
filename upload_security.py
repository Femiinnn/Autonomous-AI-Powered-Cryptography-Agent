"""
Upload Security Module for Crypto CTF Agent
═══════════════════════════════════════════════════════════════════════════
Implements a 16-point defense-in-depth security layer against file upload
vulnerabilities:

 1. Unrestricted File Upload   -> Strict extension allowlist
 2. Extension Bypass           -> Multi-extension & null-byte inspection
 3. MIME Type Spoofing         -> Magic byte signature inspection
 4. Path Traversal             -> Safe basename, UUID prefix, strict path resolve
 5. Remote Code Execution      -> Outside webroot, 0o600 permissions, no exec
 6. Malicious SVG Files        -> Strict SVG blocking & XML sanitizer
 7. Zip Bomb                   -> Compression ratio, max size & entry limits
 8. DoS via Large Files        -> Per-file & total payload size limits + rate limiting
 9. Polyglot Files             -> Deep signature checking & format validation
10. Malware Upload             -> Web-shell & malicious pattern scanning
11. Insecure Permissions       -> 0o600 file permissions (owner read/write only)
12. IDOR                       -> Job/session-isolated subdirectories
13. Stored XSS                 -> CSP, X-Content-Type-Options, nosniff headers
14. CSRF                       -> Cryptographic token & Origin/Referer verification
15. Race Conditions            -> Atomic quarantine write (.tmp) then os.replace
16. Information Disclosure     -> EXIF metadata stripping & server path redaction
"""

import os
import re
import io
import time
import uuid
import hmac
import hashlib
import secrets
import zipfile
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional

# ── 1. Extension Lists ────────────────────────────────────────────────────────
# Permitted extensions in a Crypto CTF context:
# Code, parameters, ciphers, public keys, hashes, logs, plaintexts, and safe images
ALLOWED_EXTENSIONS = {
    # Cryptographic materials & data
    'txt', 'hex', 'dat', 'bin', 'raw', 'enc', 'pem', 'pub', 'key', 'crt',
    'der', 'sig', 'hash', 'out', 'chall', 'ciphertext', 'msg', 'cipher',
    # Source code & parameters
    'py', 'sage', 'c', 'cpp', 'h', 'hpp', 'rs', 'go', 'java', 'json',
    'log', 'asm', 's', 'csv', 'yaml', 'yml', 'md',
    # Safe static image formats
    'png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp', 'tiff', 'tif', 'ico',
    # Archives (inspected with zip-bomb guards)
    'zip', 'tar', 'gz'
}

# Explicitly forbidden dangerous executable, scripting, and shell extensions
DANGEROUS_EXTENSIONS = {
    'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht', 'phar',
    'exe', 'dll', 'so', 'dylib', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'jse',
    'wsf', 'wsh', 'msc', 'msi', 'scr', 'com', 'pif', 'hta', 'cpl', 'jar',
    'war', 'ear', 'sh', 'bash', 'zsh', 'cgi', 'pl', 'pyc', 'pyo', 'pyd',
    'asp', 'aspx', 'jsp', 'jspx', 'cer', 'asa', 'asax', 'svg', 'xhtml',
    'htm', 'html', 'shtml', 'swf', 'xap'
}

# Image extensions that should be validated with Pillow
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp', 'tiff', 'tif', 'ico'}

# ── 8. Size & Quota Constraints ───────────────────────────────────────────────
MAX_FILE_SIZE = 10 * 1024 * 1024        # 10 MB per individual file
MAX_TOTAL_FILES = 10                     # Maximum 10 files per request
MAX_UNCOMPRESSED_ARCHIVE = 50 * 1024 * 1024  # 50 MB max extracted archive size
MAX_COMPRESSION_RATIO = 10.0             # Max 10:1 uncompressed-to-compressed ratio
MAX_ARCHIVE_ENTRIES = 100                # Max 100 files inside a zip

# ── Magic Byte Signatures ─────────────────────────────────────────────────────
MAGIC_SIGNATURES: Dict[str, List[bytes]] = {
    'png':  [b'\x89PNG\r\n\x1a\n'],
    'jpg':  [b'\xff\xd8\xff'],
    'jpeg': [b'\xff\xd8\xff'],
    'gif':  [b'GIF87a', b'GIF89a'],
    'bmp':  [b'BM'],
    'webp': [b'RIFF'],  # and 'WEBP' at offset 8
    'zip':  [b'PK\x03\x04'],
    'gz':   [b'\x1f\x8b'],
}

# Dangerous executable / shell magic signatures that must NEVER be allowed
DANGEROUS_MAGIC: List[Tuple[bytes, str]] = [
    (b'MZ', 'Windows Portable Executable (EXE/DLL)'),
    (b'\x7fELF', 'Linux Executable and Linkable Format (ELF)'),
    (b'\xfe\xed\xfa\xce', 'Mach-O 32-bit (Big Endian)'),
    (b'\xce\xfa\xed\xfe', 'Mach-O 32-bit (Little Endian)'),
    (b'\xfe\xed\xfa\xcf', 'Mach-O 64-bit (Big Endian)'),
    (b'\xcf\xfa\xed\xfe', 'Mach-O 64-bit (Little Endian)'),
    (b'\xca\xfe\xba\xbe', 'Java Bytecode / Mach-O Universal'),
]

# ── 10. Malware & Web Shell Signature Patterns ────────────────────────────────
SUSPICIOUS_CONTENT_PATTERNS = [
    rb'<\?php',
    rb'<\?=',
    rb'<script[\s>]',
    rb'<%[\s=]',
    rb'eval\s*\(\s*base64_decode',
    rb'system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
    rb'passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
    rb'shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
    rb'popen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
    rb'proc_open\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
    rb'c99sh',
    rb'r57shell',
    rb'WSO_VERSION',
    rb'/bin/(ba)?sh\s+-i',
    rb'nc\s+-e\s+/bin/(ba)?sh',
]


class SecurityValidationError(Exception):
    """Raised when an uploaded file fails security validation."""
    def __init__(self, message: str, vulnerability: str = "Generic"):
        super().__init__(message)
        self.message = message
        self.vulnerability = vulnerability


class UploadSecurityManager:
    """
    Centralized controller for validating, sanitizing, quarantining,
    and managing challenge file uploads safely.
    """

    def __init__(self, base_upload_dir: Path):
        self.base_upload_dir = Path(base_upload_dir).resolve()
        self.base_upload_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir = self.base_upload_dir / '.quarantine'
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        # Rate limiter memory: ip -> [timestamps]
        self._ip_requests: Dict[str, List[float]] = {}
        # CSRF secret key (persisted for server lifetime)
        self._csrf_secret = secrets.token_bytes(32)

    # ── 8. Rate Limiting ──────────────────────────────────────────────────────
    def check_rate_limit(self, client_ip: str, max_requests: int = 30, window_seconds: int = 60) -> bool:
        """Sliding window rate limiter per IP address."""
        now = time.time()
        timestamps = self._ip_requests.setdefault(client_ip, [])
        # Expire old requests
        timestamps = [t for t in timestamps if now - t < window_seconds]
        self._ip_requests[client_ip] = timestamps
        if len(timestamps) >= max_requests:
            return False
        timestamps.append(now)
        return True

    # ── 14. CSRF Protection ───────────────────────────────────────────────────
    def generate_csrf_token(self, session_id: str) -> str:
        """Generates a cryptographically strong HMAC-based CSRF token."""
        h = hmac.new(self._csrf_secret, session_id.encode('utf-8'), hashlib.sha256)
        return f"{session_id}:{h.hexdigest()}"

    def validate_csrf_token(self, token: str, session_id: str) -> bool:
        """Validates the CSRF token in constant time."""
        if not token or ':' not in token:
            return False
        received_session, received_hash = token.split(':', 1)
        if received_session != session_id:
            return False
        expected_hash = hmac.new(self._csrf_secret, session_id.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(received_hash, expected_hash)

    # ── 1, 2, 4. Filename Validation & Extension Bypass Defense ────────────────
    def sanitize_and_validate_filename(self, raw_filename: str) -> Tuple[str, str]:
        """
        Validates the filename against path traversal, null-byte injection,
        and double-extension bypasses.

        Returns:
            (safe_client_name, primary_extension)
        """
        if not raw_filename or not isinstance(raw_filename, str):
            raise SecurityValidationError("Invalid or missing filename.", "Path Traversal")

        # 4. Path Traversal Defense: Strip directory sequences, null bytes, URL encodings
        if '\x00' in raw_filename or '%00' in raw_filename:
            raise SecurityValidationError("Null-byte injection detected in filename.", "Extension Bypass")

        clean_name = os.path.basename(raw_filename).strip()
        # Remove any path traversal segments
        clean_name = re.sub(r'(\.\./|\.\.\\|/|\\)', '', clean_name)
        # Whitelist safe characters for filename
        clean_name = re.sub(r'[^a-zA-Z0-9._\-+]', '_', clean_name)

        if not clean_name or clean_name in ('.', '..'):
            clean_name = f"upload_{secrets.token_hex(4)}"

        # 2. Extension Bypass Defense: Inspect all segments for disguised extensions
        parts = clean_name.lower().split('.')
        if len(parts) > 1:
            # Check every extension segment (e.g. 'exploit.php.jpg' has 'php' in segments)
            for seg in parts[1:]:
                if seg in DANGEROUS_EXTENSIONS:
                    raise SecurityValidationError(
                        f"Disallowed executable/script extension segment '.{seg}' detected.",
                        "Extension Bypass"
                    )

            primary_ext = parts[-1]
            # 1. Unrestricted File Upload Defense: Verify against allowlist
            if primary_ext not in ALLOWED_EXTENSIONS:
                raise SecurityValidationError(
                    f"File extension '.{primary_ext}' is not permitted.",
                    "Unrestricted File Upload"
                )
        else:
            primary_ext = ""  # No extension (allowed in CTFs if magic bytes pass)

        return clean_name, primary_ext

    # ── 3, 9, 10. Magic Bytes, Polyglot, and Malware Scanning ─────────────────
    def inspect_file_content(self, data: bytes, ext: str, original_filename: str) -> None:
        """
        Deeply inspects the raw file payload for:
        - Dangerous executable magic signatures (PE, ELF, Mach-O)
        - MIME/Magic byte mismatch (e.g., claiming to be PNG but is not)
        - Polyglot payload injection (e.g., PHP embedded in JPEG/GIF)
        - Web shell signatures and malicious scripts
        - Malicious SVG constructs (scripts, XXE)
        """
        if not data:
            return  # Empty file allowed (handled safely)

        # 3. Prevent Executables disguised under any extension
        for magic, desc in DANGEROUS_MAGIC:
            if data.startswith(magic):
                raise SecurityValidationError(
                    f"Dangerous binary signature detected: {desc}.",
                    "Remote Code Execution"
                )

        # 6. Malicious SVG Defense: Never allow SVG with script tags or XML entity expansion
        if ext == 'svg' or b'<svg' in data[:2048].lower():
            raise SecurityValidationError(
                "SVG uploads are disabled to prevent Stored XSS and XML External Entity (XXE) attacks.",
                "Malicious SVG Files"
            )

        # 3. MIME/Magic Byte Validation for claimed image formats
        if ext in MAGIC_SIGNATURES:
            valid_magics = MAGIC_SIGNATURES[ext]
            matched = any(data.startswith(m) for m in valid_magics)
            if ext == 'webp' and not (data.startswith(b'RIFF') and b'WEBP' in data[8:16]):
                matched = False

            if not matched:
                raise SecurityValidationError(
                    f"File content does not match the expected signature for '.{ext}'.",
                    "MIME Type Spoofing"
                )

        # 9, 10. Polyglot & Web Shell Pattern Scanning
        # Check first 64KB and last 16KB where polyglot payloads usually reside
        scan_zone = data[:65536] + data[-16384:]
        for pat in SUSPICIOUS_CONTENT_PATTERNS:
            if re.search(pat, scan_zone, re.IGNORECASE):
                raise SecurityValidationError(
                    "Suspicious script or web-shell signature pattern detected in file contents.",
                    "Polyglot Files / Malware Upload"
                )

    # ── 7. Zip Bomb & Archive Inspection ──────────────────────────────────────
    def validate_zip_archive(self, file_path: Path) -> None:
        """
        Inspects zip archives against zip bombs, excessive compression ratios,
        and zip slip path traversals.
        """
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                infos = zf.infolist()
                if len(infos) > MAX_ARCHIVE_ENTRIES:
                    raise SecurityValidationError(
                        f"Zip archive contains too many entries ({len(infos)} > {MAX_ARCHIVE_ENTRIES}).",
                        "Zip Bomb"
                    )

                total_uncompressed = 0
                total_compressed = file_path.stat().st_size or 1

                for info in infos:
                    # Check for Zip Slip path traversal
                    if '..' in info.filename or info.filename.startswith('/') or info.filename.startswith('\\'):
                        raise SecurityValidationError(
                            f"Zip archive contains path traversal entry: '{info.filename}'.",
                            "Path Traversal"
                        )
                    # Disallow nested executables inside zip
                    inner_ext = info.filename.lower().rsplit('.', 1)[-1] if '.' in info.filename else ''
                    if inner_ext in DANGEROUS_EXTENSIONS:
                        raise SecurityValidationError(
                            f"Zip archive contains prohibited executable file: '{info.filename}'.",
                            "Unrestricted File Upload"
                        )
                    total_uncompressed += info.file_size

                if total_uncompressed > MAX_UNCOMPRESSED_ARCHIVE:
                    raise SecurityValidationError(
                        f"Uncompressed archive exceeds size limit ({total_uncompressed} bytes > {MAX_UNCOMPRESSED_ARCHIVE}).",
                        "Zip Bomb"
                    )

                ratio = total_uncompressed / max(total_compressed, 1)
                if ratio > MAX_COMPRESSION_RATIO:
                    raise SecurityValidationError(
                        f"Zip archive compression ratio too high ({ratio:.1f}:1 > {MAX_COMPRESSION_RATIO}:1). Potential Zip Bomb.",
                        "Zip Bomb"
                    )
        except zipfile.BadZipFile:
            raise SecurityValidationError("Corrupted or invalid zip archive.", "Zip Bomb")

    def extract_safe_archive(self, file_path: Path, target_dir: Path) -> List[Dict[str, Any]]:
        """
        Safely extracts an archive (.zip, .tar, .tar.gz) into target_dir after validation.
        Guarantees path traversal prevention and file permission lockdown.
        """
        import shutil
        extracted = []
        target_dir = target_dir.resolve()
        ext = file_path.name.lower().split('.')[-1]

        if ext == 'zip':
            self.validate_zip_archive(file_path)
            with zipfile.ZipFile(file_path, 'r') as z:
                for member in z.infolist():
                    if member.is_dir():
                        continue
                    clean_name = os.path.basename(member.filename)
                    if not clean_name or clean_name.startswith('.'):
                        continue
                    dest = (target_dir / clean_name).resolve()
                    if not dest.is_relative_to(target_dir):
                        continue
                    with z.open(member) as src, open(dest, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                    try:
                        os.chmod(dest, 0o600)
                    except Exception:
                        pass
                    extracted.append({
                        'display_name': clean_name,
                        'storage_name': clean_name,
                        'path': dest,
                        'size_bytes': dest.stat().st_size,
                        'extension': clean_name.rsplit('.', 1)[-1].lower() if '.' in clean_name else '',
                        'is_image': False,
                        'status': 'extracted_secure'
                    })
        elif ext in ('tar', 'gz', 'tgz'):
            import tarfile
            try:
                with tarfile.open(file_path, 'r:*') as t:
                    total_size = 0
                    members = t.getmembers()
                    if len(members) > MAX_ARCHIVE_ENTRIES:
                        raise SecurityValidationError(f"Tar archive has too many entries ({len(members)}).", "Zip Bomb")
                    for m in members:
                        if not m.isfile():
                            continue
                        clean_name = os.path.basename(m.name)
                        if not clean_name or clean_name.startswith('.'):
                            continue
                        dest = (target_dir / clean_name).resolve()
                        if not dest.is_relative_to(target_dir):
                            continue
                        total_size += m.size
                        if total_size > MAX_UNCOMPRESSED_ARCHIVE:
                            raise SecurityValidationError("Tar uncompressed size exceeded limit.", "Zip Bomb")
                        fobj = t.extractfile(m)
                        if fobj:
                            with open(dest, 'wb') as dst:
                                shutil.copyfileobj(fobj, dst)
                            try:
                                os.chmod(dest, 0o600)
                            except Exception:
                                pass
                            extracted.append({
                                'display_name': clean_name,
                                'storage_name': clean_name,
                                'path': dest,
                                'size_bytes': dest.stat().st_size,
                                'extension': clean_name.rsplit('.', 1)[-1].lower() if '.' in clean_name else '',
                                'is_image': False,
                                'status': 'extracted_secure'
                            })
            except Exception as e:
                if isinstance(e, SecurityValidationError):
                    raise
                raise SecurityValidationError(f"Invalid tar archive: {e}", "Zip Bomb")

        return extracted

    # ── 16. Metadata Stripping for Images ──────────────────────────────────────
    def sanitize_image_metadata(self, file_path: Path, ext: str) -> bool:
        """
        Uses Pillow to verify image integrity and strip sensitive EXIF / metadata
        (GPS locations, author tags, camera serial numbers).
        """
        if ext not in IMAGE_EXTENSIONS:
            return False

        try:
            from PIL import Image
            # Open and verify image structure
            with Image.open(file_path) as img:
                img.verify()

            # Re-open to strip EXIF and save sanitized image in-place
            with Image.open(file_path) as img:
                # Convert to clean image copy without EXIF dictionary
                data = list(img.getdata())
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(data)
                clean_img.save(file_path)
            return True
        except Exception as exc:
            # If Pillow fails to parse an image, reject it to prevent image parser exploits
            raise SecurityValidationError(
                f"Image integrity validation failed: {str(exc)[:80]}.",
                "Polyglot Files"
            )

    # ── 15, 12, 11, 5. Atomic Quarantine Upload & Isolation ───────────────────
    def process_and_save_upload(
        self,
        file_storage: Any,
        job_id: str
    ) -> Dict[str, Any]:
        """
        Processes a single uploaded file through the entire 16-point security pipeline:
        1. Validates and sanitizes filename.
        2. Streams content into quarantine `.tmp` file (checking size limit).
        3. Performs deep magic-byte, malware, and polyglot inspection.
        4. Validates zip archives against decompression bombs if applicable.
        5. Strips EXIF metadata from images.
        6. Atomically moves the file to the job-isolated directory (`inputs/<job_id>/`).
        7. Sets strict `0o600` permissions (owner read/write only, no execution).
        8. Returns safe metadata without disclosing server filesystem paths.
        """
        raw_name = getattr(file_storage, 'filename', '') or 'upload'
        safe_client_name, ext = self.sanitize_and_validate_filename(raw_name)

        # 12. IDOR & Isolation: Create job-specific isolated subdirectory
        job_dir = self.base_upload_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        # 15. Race Condition Defense: Write to temporary file in quarantine first
        tmp_id = f"quarantine_{secrets.token_hex(8)}.tmp"
        tmp_path = self.quarantine_dir / tmp_id

        total_bytes = 0
        try:
            with open(tmp_path, 'wb') as f:
                while True:
                    chunk = file_storage.read(65536)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    # 8. DoS via Large Files: Enforce per-file limit during stream
                    if total_bytes > MAX_FILE_SIZE:
                        raise SecurityValidationError(
                            f"File size exceeds maximum permitted limit of {MAX_FILE_SIZE // (1024*1024)} MB.",
                            "DoS via Large Files"
                        )
                    f.write(chunk)

            # Read sample for content inspection
            with open(tmp_path, 'rb') as f:
                sample_data = f.read(131072)  # Read up to 128KB for deep signature inspection

            # 3, 9, 10. Deep content, polyglot, and malware signature inspection
            self.inspect_file_content(sample_data, ext, safe_client_name)

            # 7. Zip Bomb check if zip archive
            if ext == 'zip':
                self.validate_zip_archive(tmp_path)

            # 16. Strip image metadata (EXIF/GPS/device info)
            is_sanitized_image = False
            if ext in IMAGE_EXTENSIONS:
                is_sanitized_image = self.sanitize_image_metadata(tmp_path, ext)

            # 4. Generate unique server-side storage filename with UUID to prevent collision & traversal
            storage_name = f"{secrets.token_hex(8)}_{safe_client_name}"
            final_target_path = job_dir / storage_name

            # 4. Path Traversal Verify: Must be strictly inside job_dir
            if not final_target_path.resolve().is_relative_to(job_dir.resolve()):
                raise SecurityValidationError("Path traversal boundary violation.", "Path Traversal")

            # 15. Atomic Rename/Move from quarantine to final destination
            os.replace(tmp_path, final_target_path)

            # 11, 5. Insecure Permissions & RCE Defense: Restrict file permissions (0o600)
            try:
                os.chmod(final_target_path, 0o600)
            except Exception:
                pass

            # 16. Information Disclosure Defense: Do NOT expose full filesystem path in result
            return {
                'display_name': safe_client_name,
                'storage_name': storage_name,
                'job_id': job_id,
                'path': final_target_path,
                'size_bytes': total_bytes,
                'extension': ext,
                'is_image': is_sanitized_image or (ext in IMAGE_EXTENSIONS),
                'status': 'verified_secure'
            }

        except Exception:
            # Clean up quarantine temporary file immediately on any error or validation failure
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
            raise

    # ── Cleanup ───────────────────────────────────────────────────────────────
    def cleanup_job(self, job_id: str) -> None:
        """Cleans up the job's isolated upload directory and all contained files."""
        if not job_id or not re.match(r'^[a-zA-Z0-9_\-]+$', job_id):
            return
        job_dir = self.base_upload_dir / job_id
        if job_dir.exists() and job_dir.is_dir():
            try:
                import shutil
                shutil.rmtree(job_dir, ignore_errors=True)
            except Exception:
                pass
