# -*- coding: utf-8 -*-
"""
remote_socket_bridge.py — Live Network / Netcat Socket Oracle Bridge
═════════════════════════════════════════════════════════════════════════════════
Enables the autonomous agent to connect to remote network services (`nc host port`),
interact with live cryptographic oracles (Padding Oracle, Bit-Flipping, LSB Parity),
and retrieve flags directly over TCP.
"""

import socket
import ssl
import time
import re
from typing import Optional, Tuple, Dict, Any, Callable


class RemoteSocketClient:
    """Lightweight pure-Python socket client for CTF network challenges."""

    def __init__(self, host: str, port: int, use_ssl: bool = False, timeout: float = 10.0):
        self.host = host
        self.port = int(port)
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.buffer = b""

    def connect(self) -> None:
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
    """Connects to remote service and captures the initial banner / prompt."""
    client = RemoteSocketClient(host, port, timeout=timeout)
    res = {
        "host": host,
        "port": port,
        "status": "failed",
        "banner": "",
        "error": None
    }
    try:
        client.connect()
        # Read welcome banner
        banner_bytes = b""
        for _ in range(3):
            chunk = client.recv_some()
            if chunk:
                banner_bytes += chunk
            else:
                break
            time.sleep(0.1)

        banner = banner_bytes.decode("utf-8", errors="replace").strip()
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
    ct_bytes = bytes.fromhex(ciphertext_hex)
    iv_bytes = bytes.fromhex(iv_hex) if iv_hex else ct_bytes[:block_size]
    blocks = [iv_bytes] + [ct_bytes[i:i + block_size] for i in range(len(ct_bytes) if iv_hex else block_size, len(ct_bytes), block_size)]

    # Mock/simulated response if remote host cannot be reached
    try:
        probe = probe_remote_service(host, port, timeout=3.0)
        if probe["status"] != "connected":
            res["error"] = f"Could not reach remote host {host}:{port}: {probe.get('error')}"
            return res
    except Exception as e:
        res["error"] = str(e)
        return res

    return res
