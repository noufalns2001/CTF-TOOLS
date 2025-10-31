#!/usr/bin/env python3
# decode_probe.py
# Usage: python3 decode_probe.py numbers.txt

import sys, os, re, itertools, zlib, gzip, bz2, lzma
from collections import Counter

# -------------------------
# Helpers
# -------------------------
def parse_numbers_file(path):
    txt = open(path, "r", encoding="utf-8", errors="ignore").read()
    nums = [int(x) for x in re.findall(r'-?\d+', txt)]
    return nums

def to_bytes_signed(nums):
    return bytes([n & 0xff for n in nums])

def printable_ratio(bs):
    if not bs:
        return 0.0
    good = sum(32 <= c < 127 for c in bs)
    return good / len(bs)

def find_printable_runs(bs, min_len=6):
    runs = []
    cur = bytearray()
    cur_i = 0
    for i, b in enumerate(bs):
        if 32 <= b < 127:
            if not cur:
                cur_i = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                runs.append((cur_i, bytes(cur)))
            cur = bytearray()
    if len(cur) >= min_len:
        runs.append((cur_i, bytes(cur)))
    return runs

MAGICS = {
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"%PDF-": "PDF",
    b"PK\x03\x04": "ZIP",
    b"\x1f\x8b": "GZIP",
    b"7z\xbc\xaf'": "7Z",
    b"MZ": "PE",
    b"\x7fELF": "ELF",
    b"x\x9c": "zlib?"  # note: zlib commonly 0x78 0x9c
}

def detect_magic(bs):
    found = []
    for sig, name in MAGICS.items():
        idx = bs.find(sig)
        if idx != -1:
            found.append((name, idx, sig))
    return found

def save_candidate(name, bs):
    os.makedirs("candidates", exist_ok=True)
    fn = os.path.join("candidates", f"{name}.bin")
    with open(fn, "wb") as f:
        f.write(bs)
    return fn

# -------------------------
# Probes
# -------------------------
def probe_magic(bs):
    m = detect_magic(bs)
    if m:
        print("MAGIC signatures found:", m)

def try_decompressions(bs, tag):
    # try zlib, gzip, bz2, lzma
    tries = []
    try:
        out = zlib.decompress(bs)
        tries.append(("zlib", out))
    except Exception:
        pass
    try:
        out = gzip.decompress(bs)
        tries.append(("gzip", out))
    except Exception:
        pass
    try:
        out = bz2.decompress(bs)
        tries.append(("bz2", out))
    except Exception:
        pass
    try:
        out = lzma.decompress(bs)
        tries.append(("lzma", out))
    except Exception:
        pass

    for name, out in tries:
        pr = printable_ratio(out)
        print(f"[{tag}] decompressed with {name}, printable={pr:.3f}, len={len(out)}")
        if pr > 0.6 or b"flag{" in out or b"CTF{" in out or b"cyber" in out:
            fn = save_candidate(f"{tag}_decomp_{name}", out)
            print("  PROMISING -> saved to", fn)

def try_single_byte_xor(bs):
    print("Trying single-byte XOR (0..255)...")
    for k in range(256):
        xb = bytes([b ^ k for b in bs])
        pr = printable_ratio(xb)
        if pr > 0.6 or b"flag{" in xb or b"CTF{" in xb or b"cyber" in xb:
            print(f"  KEY {k:03d} printable={pr:.3f} contains_flag={b'flag{' in xb}")
            fn = save_candidate(f"xor_{k:03d}", xb)
            print("    saved ->", fn)
        # also try decompressing some xor results for magic headers
        if xb[:4].startswith(b'\x78') or xb[:2] == b'\x1f\x8b' or printable_ratio(xb[:32])>0.8:
            try_decompressions(xb, f"xor_{k:03d}")

def try_repeating_xor_printable_keys(bs, max_klen=8):
    print("Trying repeating-key XOR with printable keys (len 1..%d)..."%max_klen)
    # printable keyspace: letters+digits (you can expand)
    keychars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    # try small key lengths; brute force all combos up to len 4 reasonably, lengths 5-8 sample some combos
    for klen in range(1, max_klen+1):
        print(" keylen=", klen)
        if klen <= 3:
            for key in itertools.product(keychars, repeat=klen):
                keyb = bytes(key)
                xb = bytes([b ^ keyb[i % klen] for i, b in enumerate(bs)])
                pr = printable_ratio(xb)
                if pr > 0.7 or b"flag{" in xb or b"CTF{" in xb or b"cyber" in xb:
                    name = f"rkx_{keyb.decode('ascii')}"
                    fn = save_candidate(name, xb)
                    print("  PROMISING key=", keyb, "->", fn, "pr=", pr)
        else:
            # sample some keys for larger klen (random-ish selection to keep runtime sane)
            import random
            for _ in range(2000):
                keyb = bytes(random.choice(keychars) for _ in range(klen))
                xb = bytes([b ^ keyb[i % klen] for i, b in enumerate(bs)])
                pr = printable_ratio(xb)
                if pr > 0.72 or b"flag{" in xb:
                    name = f"rkx_sample_{keyb.decode('ascii',errors='ignore')}"
                    fn = save_candidate(name, xb)
                    print("  PROMISING key(sample)=", keyb, "->", fn, "pr=", pr)

def try_additive_shifts(bs):
    print("Trying additive shifts (subtracting k mod 256)...")
    for k in range(256):
        xb = bytes([(b - k) & 0xff for b in bs])
        pr = printable_ratio(xb)
        if pr > 0.7 or b"flag{" in xb or b"CTF{" in xb or b"cyber" in xb:
            print(f"  shift -{k:03d} printable={pr:.3f}")
            fn = save_candidate(f"shift_minus_{k:03d}", xb)
            print("    saved ->", fn)
        # try decompress if starts like zlib/gzip
        if xb[:2] in (b'\x78\x9c', b'\x1f\x8b'):
            try_decompressions(xb, f"shift_minus_{k:03d}")

def quick_stats(bs):
    print("len:", len(bs))
    print("printable ratio:", printable_ratio(bs))
    runs = find_printable_runs(bs)
    print("printable runs (len>=6):", len(runs))
    if runs:
        for i,(idx,txt) in enumerate(runs[:10]):
            print(f"  run#{i} @ {idx} -> {txt[:80]}")
    mc = Counter(bs)
    print("byte histogram (top 10):", mc.most_common(10))
    magic = detect_magic(bs)
    if magic:
        print("Detected magics:", magic)

# -------------------------
# Main
# -------------------------
def main(argv):
    if len(argv) < 2:
        print("Usage: python3 decode_probe.py numbers.txt")
        return
    src = argv[1]
    nums = parse_numbers_file(src)
    bs = to_bytes_signed(nums)
    print("Parsed", len(nums), "numbers ->", len(bs), "bytes")
    quick_stats(bs)
    probe_magic(bs)

    # Try direct decompression (raw)
    try_decompressions(bs, "raw")

    # Try single-byte XOR
    try_single_byte_xor(bs)

    # Try repeating-key XOR (printable-keyspace)
    try_repeating_xor_printable_keys(bs, max_klen=6)  # change max_klen up to 8 if you want longer brute force

    # Try additive shifts (like Caesar on bytes)
    try_additive_shifts(bs)

    # Also try XOR with 0x80 (flip high bit)
    xb = bytes([b ^ 0x80 for b in bs])
    print("After XOR 0x80 printable:", printable_ratio(xb))
    if printable_ratio(xb) > 0.6 or b"flag{" in xb:
        save_candidate("xor_0x80", xb)

    print("Done. Candidates (if any) are in ./candidates/")

if __name__ == "__main__":
    main(sys.argv)