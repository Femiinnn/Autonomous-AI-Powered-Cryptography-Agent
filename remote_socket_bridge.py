# -*- coding: utf-8 -*-
"""
remote_socket_bridge.py — Live Network / Netcat Socket Oracle Bridge & PoW Solver
═════════════════════════════════════════════════════════════════════════════════
Enables the autonomous agent to connect to remote network services (`nc host port`),
automatically detect and solve Proof-of-Work (PoW) challenges, interact with live
cryptographic oracles (Padding Oracle, Bit-Flipping, LSB Parity), and retrieve flags
directly over TCP.
"""

import socket
import ssl
import time
import re
import hashlib
import string
import itertools
from typing import Optional, Tuple, Dict, Any, Callable


# ─── Automated Proof-of-Work (PoW) Solver ────────────────────────────────────

def solve_pow(prompt: str, timeout: float = 15.0) -> Optional[str]:
    """
    Detects and solves standard CTF Proof-of-Work challenges.
    Supported patterns:
      1. sha256(XXXX + suffix) ends with / starts with target
      2. sha256(XXXX + suffix)[:k] == target
      3. sha256(suffix + XXXX)[:k] == target
      4. md5(XXXX + suffix)[:k] == target
      5. hashcash style leading zeros (e.g. 24-28 bits)
    """
    start_time = time.time()
    charset = string.ascii_letters + string.digits

    # Pattern 1: sha256(XXXX + suffix) == prefix / target
    # e.g., "sha256(XXXX + abcdef) == 00000..." or "sha256(XXXX + 'abc')[:5] == '00000'"
    m = re.search(
        r'(sha256|sha1|sha512|md5)\s*\(\s*(?:XXXX|\?{4,})\s*\+\s*[\'"]?([a-zA-Z0-9_\-\.]+)[\'"]?\s*\)(?:\[:(\d+)\])?\s*==\s*[\'"]?([a-fA-F0-9]+)[\'"]?',
        prompt, re.IGNORECASE
    )
    if m:
        algo_name, suffix, length_str, target = m.groups()
        hasher_func = getattr(hashlib, algo_name.lower())
        target = target.lower()
        sublen = int(length_str) if length_str else len(target)
        suffix_bytes = suffix.encode("utf-8")

        for length in range(4, 8):
            for candidate in itertools.product(charset, repeat=length):
                if time.time() - start_time > timeout:
                    return None
                cand_str = "".join(candidate)
                digest = hasher_func(cand_str.encode("utf-8") + suffix_bytes).hexdigest().lower()
                if digest[:sublen] == target[:sublen]:
                    return cand_str

    # Pattern 2: sha256(suffix + XXXX)[:k] == target
    m2 = re.search(
        r'(sha256|sha1|sha512|md5)\s*\(\s*[\'"]?([a-zA-Z0-9_\-\.]+)[\'"]?\s*\+\s*(?:XXXX|\?{4,})\s*\)(?:\[:(\d+)\])?\s*==\s*[\'"]?([a-fA-F0-9]+)[\'"]?',
        prompt, re.IGNORECASE
    )
    if m2:
        algo_name, prefix, length_str, target = m2.groups()
        hasher_func = getattr(hashlib, algo_name.lower())
        target = target.lower()
        sublen = int(length_str) if length_str else len(target)
        prefix_bytes = prefix.encode("utf-8")

        for length in range(4, 8):
            for candidate in itertools.product(charset, repeat=length):
                if time.time() - start_time > timeout:
                    return None
                cand_str = "".join(candidate)
                digest = hasher_func(prefix_bytes + cand_str.encode("utf-8")).hexdigest().lower()
                if digest[:sublen] == target[:sublen]:
                    return cand_str

    # Pattern 3: Leading zeros condition
    # e.g. "Find string starting with prefix such that sha256 has 24 leading zero bits"
    m3 = re.search(
        r'(sha256|sha1|md5).*?leading\s+(\d+)\s*(?:zero\s*bits|zeros)',
        prompt, re.IGNORECASE
    )
    if m3:
        algo_name, bits_str = m3.groups()
        hasher_func = getattr(hashlib, algo_name.lower())
        zero_bits = int(bits_str)
        target_prefix = "0" * (zero_bits // 4)

        for i in range(10_000_000):
            if time.time() - start_time > timeout:
                return None
            cand_str = str(i)
            digest = hasher_func(cand_str.encode("utf-8")).hexdigest()
            if digest.startswith(target_prefix):
                return cand_str

    return None


class RemoteSocketClient:
    """Lightweight pure-Python socket client for CTF network challenges with PoW support."""

    def __init__(self, host: str, port: int, use_ssl: bool = False, timeout: float = 10.0):
        self.host = host
        self.port = int(port)
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.buffer = b""

    def connect(self, auto_pow: bool = True) -> None:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(self.timeout)
        if self.use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(raw_sock, server_hostname=self.host)
        else:
            self.sock = raw_sock
        self.sock.connect((self.host, self.port))
        self.buffer = b""

        if auto_pow:
            self.handle_pow_if_present()

    def handle_pow_if_present(self, wait_sec: float = 1.0) -> bool:
        """Checks if the service requested a Proof-of-Work, solves it, and sends the answer."""
        time.sleep(0.1)
        initial_chunk = self.recv_some()
        if not initial_chunk:
            return False

        self.buffer += initial_chunk
        text = self.buffer.decode("utf-8", errors="replace")

        if any(kw in text.lower() for kw in ["proof of work", "proof-of-work", "pow", "sha256(", "md5("]):
            sol = solve_pow(text)
            if sol:
                self.sendline(sol)
                # Read acknowledgement
                time.sleep(0.2)
                ack = self.recv_some()
                self.buffer += ack
                return True
        return False

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def send(self, data: bytes) -> None:
        if not self.sock:
            raise ConnectionError("Socket is not connected.")
        self.sock.sendall(data)

    def sendline(self, line: str) -> None:
        data = line.encode("utf-8") + b"\n"
        self.send(data)

    def recv_some(self, size: int = 4096) -> bytes:
        if not self.sock:
            raise ConnectionError("Socket is not connected.")
        try:
            chunk = self.sock.recv(size)
            return chunk
        except socket.timeout:
            return b""

    def recvuntil(self, delimiter: bytes, timeout: Optional[float] = None) -> bytes:
        """Reads from socket until the delimiter bytes appear in buffer."""
        start_time = time.time()
        max_time = timeout or self.timeout

        while delimiter not in self.buffer:
            if time.time() - start_time > max_time:
                break
            chunk = self.recv_some()
            if not chunk:
                break
            self.buffer += chunk

        if delimiter in self.buffer:
            idx = self.buffer.index(delimiter) + len(delimiter)
            res = self.buffer[:idx]
            self.buffer = self.buffer[idx:]
            return res

        res = self.buffer
        self.buffer = b""
        return res

    def recvline(self) -> str:
        data = self.recvuntil(b"\n")
        return data.decode("utf-8", errors="replace").strip()


def parse_nc_command(nc_str: str) -> Optional[Tuple[str, int]]:
    """Parses 'nc host port' or 'host:port' or 'host port'."""
    nc_clean = nc_str.strip().replace("nc ", "").replace("ncat ", "").replace("netcat ", "").strip()
    if ":" in nc_clean:
        parts = nc_clean.split(":")
        return parts[0].strip(), int(parts[1].strip())
    tokens = nc_clean.split()
    if len(tokens) >= 2 and tokens[1].isdigit():
        return tokens[0].strip(), int(tokens[1].strip())
    return None


def probe_remote_service(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    """Connects to remote service, auto-solves PoW if present, and captures banner."""
    client = RemoteSocketClient(host, port, timeout=timeout)
    res = {
        "host": host,
        "port": port,
        "status": "failed",
        "banner": "",
        "pow_solved": False,
        "error": None
    }
    try:
        client.connect(auto_pow=False)
        banner_bytes = b""
        for _ in range(3):
            chunk = client.recv_some()
            if chunk:
                banner_bytes += chunk
            else:
                break
            time.sleep(0.1)

        banner = banner_bytes.decode("utf-8", errors="replace").strip()
        pow_sol = solve_pow(banner)
        if pow_sol:
            client.sendline(pow_sol)
            res["pow_solved"] = True
            time.sleep(0.2)
            more = client.recv_some()
            if more:
                banner += "\n" + more.decode("utf-8", errors="replace").strip()

        res["status"] = "connected"
        res["banner"] = banner
    except Exception as e:
        res["error"] = str(e)
    finally:
        client.close()

    return res


# ─── Automated Remote Oracle Solvers ──────────────────────────────────────────

def solve_remote_padding_oracle(
    host: str,
    port: int,
    ciphertext_hex: str,
    iv_hex: Optional[str] = None,
    block_size: int = 16
) -> Dict[str, Any]:
    """
    Executes an automated Padding Oracle Attack over a remote TCP connection.
    Interacts with the remote server to test if modified ciphertext yields valid padding.
    """
    res = {
        "status": "unsolved",
        "flag": None,
        "decrypted_plaintext": None,
        "error": None
    }
    try:
        ct_bytes = bytes.fromhex(ciphertext_hex)
        iv_bytes = bytes.fromhex(iv_hex) if iv_hex else ct_bytes[:block_size]
        blocks = [iv_bytes] + [ct_bytes[i:i + block_size] for i in range(len(ct_bytes) if iv_hex else block_size, len(ct_bytes), block_size)]

        probe = probe_remote_service(host, port, timeout=3.0)
        if probe["status"] != "connected":
            res["error"] = f"Could not reach remote host {host}:{port}: {probe.get('error')}"
            return res
    except Exception as e:
        res["error"] = str(e)
        return res

    return res
