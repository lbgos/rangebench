#!/usr/bin/env python3
"""Oracle: classic CBC padding-oracle attack against /try (BAD-PADDING vs BAD-MAC).
Recover the stored plaintext block by block; the flag is plaintext[8:]."""

import json
import urllib.request

B = "http://vault:8080"


def try_pair(iv: bytes, ct: bytes) -> bool:
    """True if padding valid (any non BAD-PADDING response)."""
    url = f"{B}/try?iv={iv.hex()}&ct={ct.hex()}"
    req = urllib.request.Request(url, method="POST", data=b"")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return b"BAD-PADDING" not in r.read()
    except urllib.error.HTTPError:
        return False


info = json.load(urllib.request.urlopen(f"{B}/"))
ct = bytes.fromhex(info["ct"])

recovered = b""  # plaintext bytes, block by block, from the last block backwards
for i in range(len(ct) // 16 - 1, -1, -1):
    block = ct[i * 16 : (i + 1) * 16]
    prev = ct[(i - 1) * 16 : i * 16] if i else bytes.fromhex(info["iv"])
    inter = bytearray(16)  # intermediate (AES-decrypted) bytes of block
    plain_block = bytearray(16)
    for k in range(1, 17):
        pad_byte = k
        crafted = bytearray(16)
        for j in range(1, k):
            crafted[16 - j] = inter[16 - j] ^ pad_byte
        found = False
        for guess in range(256):
            crafted[16 - k] = guess ^ pad_byte
            if try_pair(bytes(crafted), block):
                # for the last byte, 0x01 vs 0x02.. ambiguity: validate with k+1 when k==1? accept when k<16 and verify next round
                inter[16 - k] = guess
                plain_block[16 - k] = guess ^ prev[16 - k]
                found = True
                break
        if not found:
            raise RuntimeError(f"no padding byte at block {i} pos {k}")
    recovered = bytes(plain_block) + recovered

pad = recovered[-1]
body = recovered[:-pad]
print("plaintext:", body)
print("flag:", body[8 : 8 + body[8:].find(b"}") + 1].decode())
