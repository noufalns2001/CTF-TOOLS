#!/usr/bin/env python3
"""
ctf_hex_decoder.py
------------------
For CTF challenges where data looks like:
    0x2b:0xce:0x15:0x70:0xd3:0x96:...
This script:
  • Cleans and converts all 0x## bytes to binary
  • Extracts readable ASCII strings
  • Detects Base64-like text and decodes it
  • Tries XOR keys (0–255) for readable strings
  • Searches for patterns like AIB{ }, FLAG{ }, CTF{ }
"""

import re, base64, string, itertools, binascii

def parse_hex_colon(data_str):
    """Convert colon-separated 0x bytes to bytes object"""
    cleaned = re.findall(r'0x([0-9A-Fa-f]{1,2})', data_str)
    return bytes(int(x, 16) for x in cleaned)

def printable_strings(data, min_len=4):
    """Extract readable ASCII strings"""
    chars = ''.join(chr(b) if chr(b) in string.printable else ' ' for b in data)
    return re.findall(r'[ -~]{%d,}' % min_len, chars)

def looks_like_b64(s):
    return re.fullmatch(r'[A-Za-z0-9+/=]+', s) and len(s) % 4 == 0

def try_base64(s):
    try:
        out = base64.b64decode(s)
        if all(chr(c) in string.printable for c in out):
            return out.decode(errors='ignore')
    except Exception:
        pass
    return None

def try_xor(raw):
    found = []
    for k in range(256):
        x = bytes(b ^ k for b in raw)
        text = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in x)
        if any(flag in text for flag in ("FLAG{", "AIB{", "CTF{")):
            found.append((k, text))
    return found

def main():
    fname = input("Enter data file (e.g., conn.txt): ").strip()
    data = open(fname).read()
    raw = parse_hex_colon(data)
    print(f"[i] Parsed {len(raw)} bytes")

    # Save binary
    open("decoded.bin", "wb").write(raw)
    print("[+] Wrote binary to decoded.bin")

    # Extract readable strings
    strings_found = printable_strings(raw)
    print(f"[i] Found {len(strings_found)} readable strings:")
    for s in strings_found:
        print("   ", s)
        if looks_like_b64(s):
            decoded = try_base64(s)
            if decoded:
                print("   [+] Base64 decoded →", decoded)

    # XOR scan
    print("\n[i] Trying XOR sweep (0–255)...")
    xor_hits = try_xor(raw)
    for k, txt in xor_hits:
        print(f"   [+] XOR key 0x{k:02x} → {txt[:120]}")

    # Flag pattern search
    text = ''.join(chr(b) if chr(b) in string.printable else ' ' for b in raw)
    for pat in ("FLAG{", "AIB{", "CTF{"):
        if pat in text:
            start = text.index(pat)
            print(f"[+] Possible flag near offset {start}:")
            print(text[start:start+120])

if __name__ == "__main__":
    main()
