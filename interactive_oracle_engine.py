"""
interactive_oracle_engine.py - Autonomous Interactive Socket Oracle Driver
=============================================================================
Autonomous driver for live remote netcat CTF challenges.
Connects to remote services, inspects banners, detects interactive menus,
wraps network endpoints into Python callable oracle functions, and executes
real-time padding oracle, bit-flipping, or LSB parity attacks against the live server.
"""

import re
import time
from typing import Dict, List, Optional, Any, Callable, Tuple
from remote_socket_bridge import RemoteSocketClient, parse_nc_command


class InteractiveServiceSession:
    """
    Manages persistent and auto-reconnecting socket sessions with remote CTF servers.
    """
    def __init__(self, host: str, port: int, timeout: float = 6.0, ssl_wrap: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ssl_wrap = ssl_wrap
        self.client: Optional[RemoteSocketClient] = None
        self.banner: str = ""
        self.menu_options: Dict[str, str] = {}
        self.prompt_delim: str = "> "

    def connect(self) -> bool:
        """Establishes connection and reads initial banner."""
        try:
            self.client = RemoteSocketClient(self.host, self.port, timeout=self.timeout, ssl_wrap=self.ssl_wrap)
            self.client.connect()
            self.banner = self.client.recv_all_available(wait_time=0.6)
            self._parse_menu()
            return True
        except Exception as e:
            self.banner = f"Connection failed: {e}"
            return False

    def reconnect(self):
        """Cleanly reconnects if remote server drops socket."""
        self.close()
        time.sleep(0.1)
        self.connect()

    def _parse_menu(self):
        """Extracts standard CTF numbered menus and prompt delimiters."""
        for line in self.banner.splitlines():
            # Match: [1] Encrypt, 1. Decrypt, 1) Get Flag
            m = re.search(r'\[?(\d+)\]?[\.\)]\s*(.*)', line)
            if m:
                opt_num = m.group(1).strip()
                action = m.group(2).strip()
                self.menu_options[opt_num] = action

        # Determine prompt delimiter
        for candidate in ["> ", ": ", "? ", ">>> ", "$ "]:
            if candidate in self.banner:
                self.prompt_delim = candidate
                break

    def send_choice_and_get_response(self, choice: str, payload: str, expect_delim: Optional[str] = None) -> str:
        """Sends menu option, provides input payload, and returns response."""
        if not self.client:
            self.reconnect()
        try:
            self.client.sendline(choice)
            time.sleep(0.05)
            # Send payload after prompt
            self.client.sendline(payload)
            delim = expect_delim or self.prompt_delim
            return self.client.recvuntil(delim, timeout=self.timeout)
        except Exception:
            # Server might have dropped or finished; reconnect and retry once
            self.reconnect()
            try:
                self.client.sendline(choice)
                time.sleep(0.05)
                self.client.sendline(payload)
                delim = expect_delim or self.prompt_delim
                return self.client.recvuntil(delim, timeout=self.timeout)
            except Exception as e2:
                return f"Error: {e2}"

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None


class OracleAdapter:
    """
    Wraps an InteractiveServiceSession into standard cryptographic oracle callbacks.
    """
    @staticmethod
    def create_padding_oracle(
        session: InteractiveServiceSession,
        decrypt_choice: str = "2",
        valid_indicator: str = "valid",
        invalid_indicator: str = "invalid"
    ) -> Callable[[bytes], bool]:
        """
        Creates a callable `is_padding_valid(ciphertext_bytes) -> bool`
        suitable for SymmetricAttacks.attack_padding_oracle.
        """
        def oracle(ct_bytes: bytes) -> bool:
            resp = session.send_choice_and_get_response(decrypt_choice, ct_bytes.hex())
            resp_lower = resp.lower()
            if valid_indicator.lower() in resp_lower:
                return True
            if invalid_indicator.lower() in resp_lower:
                return False
            # If no clear text, check for standard errors
            return "error" not in resp_lower and "bad padding" not in resp_lower
        return oracle

    @staticmethod
    def create_rsa_parity_oracle(
        session: InteractiveServiceSession,
        query_choice: str = "1"
    ) -> Callable[[int], int]:
        """
        Creates a callable `parity_oracle(c: int) -> int` (0 for even, 1 for odd)
        suitable for RSAAttacks.attack_parity_oracle.
        """
        def oracle(c: int) -> int:
            resp = session.send_choice_and_get_response(query_choice, str(c))
            resp_lower = resp.lower()
            if "even" in resp_lower or "0" in resp_lower:
                return 0
            return 1
        return oracle


def probe_and_solve_remote_service(target: str) -> Dict[str, Any]:
    """
    High-level entry point: connects to remote service, identifies oracle type,
    and returns initial probe findings and solution status.
    """
    host, port = parse_nc_command(target)
    session = InteractiveServiceSession(host, port)
    connected = session.connect()

    res = {
        "target": f"{host}:{port}",
        "connected": connected,
        "banner": session.banner,
        "menu_options": session.menu_options,
        "detected_oracle_type": None,
        "flag": None
    }

    if not connected:
        return res

    b_lower = session.banner.lower()
    if "padding" in b_lower:
        res["detected_oracle_type"] = "Padding Oracle (CBC)"
    elif "parity" in b_lower or "even" in b_lower:
        res["detected_oracle_type"] = "RSA Parity Oracle (LSB)"
    elif "aes" in b_lower:
        res["detected_oracle_type"] = "Symmetric AES Oracle"
    elif "rsa" in b_lower:
        res["detected_oracle_type"] = "Asymmetric RSA Oracle"

    # Check if flag is already exposed directly in the banner
    flag_match = re.search(r'(flag\{.*?\}|ctf\{.*?\})', session.banner, re.IGNORECASE)
    if flag_match:
        res["flag"] = flag_match.group(1)

    session.close()
    return res
