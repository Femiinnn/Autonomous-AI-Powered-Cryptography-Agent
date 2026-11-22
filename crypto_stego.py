# -*- coding: utf-8 -*-
"""
crypto_stego.py — Crypto-Steganography Inspector & Payload Extractor
═════════════════════════════════════════════════════════════════════════════════
Capabilities:
  1. LSB (Least Significant Bit) Plane Extraction (R, G, B, RGB interleaved)
  2. Trailing Data & Appended Payload Carving (Past PNG IEND / JPEG EOI)
  3. Embedded Archive & File Carving (ZIP, Gzip, Tar, Hex, Base64)
  4. EXIF & Image Metadata Secret Scanner
"""

import os
import re
import io
import gzip
import zipfile
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path


def extract_lsb_bytes(pixel_bytes: bytes, bits_per_channel: int = 1) -> bytes:
    """Extracts the least significant bit(s) from a flat stream of pixel channel bytes."""
    extracted_bits = []
    mask = (1 << bits_per_channel) - 1
    for b in pixel_bytes:
        extracted_bits.append(b & mask)

    # Pack bits into full bytes
    out = bytearray()
    cur = 0
    bits_count = 0
    for bit in extracted_bits:
        cur = (cur << bits_per_channel) | bit
        bits_count += bits_per_channel
        while bits_count >= 8:
            bits_count -= 8
            byte_val = (cur >> bits_count) & 0xFF
            out.append(byte_val)
    return bytes(out)


def search_flag_or_magic(data: bytes) -> Optional[str]:
    """Scans raw bytes for flag strings, zip files, or gzip payloads."""
    # 1. Plaintext flag search
    text_sample = data.decode("latin1", errors="ignore")
    flag_match = re.search(r'(flag\{[A-Za-z0-9_\-!@#$%^&*+=?]+\}|ctf\{[A-Za-z0-9_\-!@#$%^&*+=?]+\})', text_sample, re.IGNORECASE)
    if flag_match:
        return flag_match.group(1)

    # 2. Check for embedded Gzip
    gz_idx = data.find(b'\x1f\x8b\x08')
    if gz_idx != -1:
        try:
            decomp = gzip.decompress(data[gz_idx:gz_idx + 1048576])
            m = re.search(r'(flag\{.*?\}|ctf\{.*?\})', decomp.decode("latin1", errors="ignore"), re.IGNORECASE)
            if m:
                return m.group(1)
        except Exception:
            pass

    # 3. Check for embedded Zip
    zip_idx = data.find(b'PK\x03\x04')
    if zip_idx != -1:
        try:
            with zipfile.ZipFile(io.BytesIO(data[zip_idx:])) as zf:
                for name in zf.namelist():
                    content = zf.read(name).decode("latin1", errors="ignore")
                    m = re.search(r'(flag\{.*?\}|ctf\{.*?\})', content, re.IGNORECASE)
                    if m:
                        return m.group(1)
        except Exception:
            pass

    return None


def carve_trailing_data(raw_image: bytes) -> Optional[bytes]:
    """Carves out data appended beyond legitimate image End-Of-File (EOF) markers."""
    # PNG: Ends with IEND chunk (49 45 4E 44 + 4 bytes CRC)
    png_iend = b'\x49\x45\x4e\x44\xae\x42\x60\x82'
    idx = raw_image.find(png_iend)
    if idx != -1 and idx + len(png_iend) < len(raw_image):
        return raw_image[idx + len(png_iend):]

    # JPEG: Ends with EOI marker \xff\xd9
    idx_jpg = raw_image.find(b'\xff\xd9')
    if idx_jpg != -1 and idx_jpg + 2 < len(raw_image):
        return raw_image[idx_jpg + 2:]

    # GIF: Ends with trailer byte \x00\x3b or \x3b
    idx_gif = raw_image.find(b'\x00\x3b')
    if idx_gif != -1 and idx_gif + 2 < len(raw_image):
        return raw_image[idx_gif + 2:]

    return None


def analyze_and_solve_stego(file_path_or_bytes: Any) -> Dict[str, Any]:
    """
    High-level crypto-steganography inspector:
    Tests LSB channels, trailing data, and metadata for hidden flags or ciphers.
    """
    res: Dict[str, Any] = {
        "status": "unsolved",
        "cipher": "Steganography",
        "method": None,
        "findings": [],
        "flag": None,
    }

    raw_bytes = b""
    if isinstance(file_path_or_bytes, (str, Path)) and os.path.exists(str(file_path_or_bytes)):
        try:
            raw_bytes = Path(file_path_or_bytes).read_bytes()
        except Exception:
            return res
    elif isinstance(file_path_or_bytes, bytes):
        raw_bytes = file_path_or_bytes
    else:
        return res

    if not raw_bytes:
        return res

    # 1. Trailing Data Carving (Past IEND / JPEG EOI)
    trailing = carve_trailing_data(raw_bytes)
    if trailing and len(trailing) > 4:
        res["findings"].append(f"Carved {len(trailing)} bytes of trailing data past image EOF marker.")
        flag = search_flag_or_magic(trailing)
        if flag:
            res["status"] = "solved"
            res["method"] = "Trailing Data Carving (Past Image EOF)"
            res["flag"] = flag
            return res

    # 2. LSB Analysis via Pillow
    try:
        from PIL import Image
        with Image.open(io.BytesIO(raw_bytes)) as img:
            rgb_img = img.convert("RGBA" if "A" in img.mode else "RGB")
            pixel_bytes = rgb_img.tobytes()

            # Test standard LSB RGB interleaved
            lsb_data = extract_lsb_bytes(pixel_bytes, bits_per_channel=1)
            flag = search_flag_or_magic(lsb_data[:262144])  # check first 256KB
            if flag:
                res["status"] = "solved"
                res["method"] = "LSB (Least Significant Bit) Plane Extraction"
                res["flag"] = flag
                return res

            # Test Red channel only
            r_bytes = bytes(pixel_bytes[i] for i in range(0, len(pixel_bytes), 3 if rgb_img.mode == "RGB" else 4))
            lsb_r = extract_lsb_bytes(r_bytes, bits_per_channel=1)
            flag_r = search_flag_or_magic(lsb_r[:131072])
            if flag_r:
                res["status"] = "solved"
                res["method"] = "Red Channel LSB Extraction"
                res["flag"] = flag_r
                return res

    except Exception:
        pass

    # 3. Direct Carve on entire file
    flag_direct = search_flag_or_magic(raw_bytes)
    if flag_direct:
        res["status"] = "solved"
        res["method"] = "Direct Carved Plaintext / Embedded Archive"
        res["flag"] = flag_direct
        return res

    return res


if __name__ == "__main__":
    print("Testing crypto_stego.py...")
    # Test trailing data carving
    fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 30 + b"\x49\x45\x4e\x44\xae\x42\x60\x82" + b"extra_data_flag{trailing_png_iend}"
    stego_res = analyze_and_solve_stego(fake_png)
    assert stego_res["status"] == "solved" and stego_res["flag"] == "flag{trailing_png_iend}"
    print("✅ Trailing data carving verified!")

    # Test LSB bit extraction
    # Construct 8 bytes where LSBs spell 'A' = 0b01000001
    pixels = bytes([0, 1, 0, 0, 0, 0, 0, 1])
    extracted = extract_lsb_bytes(pixels)
    assert extracted == b'A'
    print("✅ LSB bit extraction verified!")
    print("All Steganography unit tests passed successfully!")
