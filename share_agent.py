"""
Crypto CTF Agent - One-Click Public Link Sharing Engine
======================================================
Creates a secure public HTTPS link to share your agent with anyone
across the internet without installing third-party software, using standard SSH.
"""

import sys
import os
import re
import socket
import subprocess
import time
from pathlib import Path

def is_port_open(host='127.0.0.1', port=5000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex((host, port)) == 0

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def start_agent_if_needed():
    if is_port_open('127.0.0.1', 5000):
        print("  [+] Crypto CTF Agent server is already running on port 5000.")
        return None
    print("  [*] Starting Crypto CTF Agent server (app.py)...")
    app_py = Path(__file__).parent / "app.py"
    proc = subprocess.Popen([sys.executable, str(app_py)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(15):
        if is_port_open('127.0.0.1', 5000):
            print("  [+] Server started successfully on port 5000.")
            return proc
        time.sleep(0.5)
    print("  [!] Warning: Port 5000 did not become ready in 7 seconds.")
    return proc

def main():
    print("=" * 70)
    print("   CRYPTO CTF AGENT - INSTANT PUBLIC SHARING LINK GENERATOR")
    print("=" * 70)

    server_proc = start_agent_if_needed()
    lan_ip = get_lan_ip()

    print("\n  [*] Establishing secure public HTTPS tunnel via SSH...")
    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-R", "80:127.0.0.1:5000",
        "nokey@localhost.run"
    ]

    try:
        tunnel_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
    except Exception as e:
        print(f"  [!] Failed to execute ssh: {e}")
        return

    public_url = None
    print("  [*] Waiting for public domain assignment...")

    while True:
        line = tunnel_proc.stdout.readline()
        if not line:
            if tunnel_proc.poll() is not None:
                break
            continue
        
        # Look for https://...lhr.life or similar
        match = re.search(r'(https://[a-zA-Z0-9\.\-]+\.lhr\.life)', line)
        if match:
            public_url = match.group(1)
            break

    if public_url:
        print("\n" + "=" * 70)
        print("   LINK GENERATED SUCCESSFULLY! GIVE THIS TO THE OTHER PERSON:")
        print("=" * 70)
        print(f"\n   Public Link (Accessible ANYWHERE in the world):")
        print(f"   --> {public_url}")
        print(f"\n   Local Wi-Fi Link (Same network / Wi-Fi):")
        print(f"   --> http://{lan_ip}:5000")
        print(f"\n   Local Machine Link:")
        print(f"   --> http://localhost:5000")
        print("=" * 70)
        print("\n   Keep this window open to maintain the link.")
        print("   Press Ctrl+C to close and disconnect the link.\n")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  [*] Shutting down tunnel...")
            tunnel_proc.terminate()
            if server_proc:
                server_proc.terminate()
            print("  [+] Disconnected.")
    else:
        print("  [!] Could not parse tunnel URL. Tunnel output:")
        try:
            out, _ = tunnel_proc.communicate(timeout=3)
            print(out)
        except Exception:
            pass

if __name__ == "__main__":
    main()
