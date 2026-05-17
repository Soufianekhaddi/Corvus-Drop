#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Corvus Drop - Bibliothèque Cryptographique FROM SCRATCH
======================================================
Implémentation complète en pur Python des primitives de sécurité :
1. Dérivation de clé (KDF) : PBKDF2-HMAC-SHA256
2. Chiffrement symétrique : IETF ChaCha20 (256 bits, nonce 96 bits)
3. Cryptographie sur les Courbes Elliptiques (ECC) : SECP256R1 (NIST P-256)
4. Signatures numériques : ECDSA (SHA-256)
5. Sérialisation PEM personnalisée (Format JSON encapsulé)
"""

import os
import json
import hashlib
import hmac

# =====================================================================
# 1. PBKDF2-HMAC-SHA256 (KDF)
# =====================================================================
def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    hLen = 32
    if dklen > (2**32 - 1) * hLen:
        raise ValueError("dklen too long")
    
    def F(p, s, c, i):
        u = hmac.new(p, s + i.to_bytes(4, 'big'), hashlib.sha256).digest()
        ret = u
        for _ in range(1, c):
            u = hmac.new(p, u, hashlib.sha256).digest()
            ret = bytes(a ^ b for a, b in zip(ret, u))
        return ret

    l = (dklen + hLen - 1) // hLen
    derived_key = b""
    for i in range(1, l + 1):
        derived_key += F(password, salt, iterations, i)
        
    return derived_key[:dklen]


# =====================================================================
# 2. CHACHA20 (STREAM CIPHER RFC 7539)
# =====================================================================
def rotate_left(x: int, n: int) -> int:
    return ((x << n) & 0xffffffff) | ((x & 0xffffffff) >> (32 - n))

def chacha20_quarter_round(x: list, a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate_left(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate_left(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate_left(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate_left(x[b] ^ x[c], 7)

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [
        0x61787065, 0x3320646e, 0x79622d32, 0x6b206574,  # "expand 32-byte k"
        int.from_bytes(key[0:4], "little"),
        int.from_bytes(key[4:8], "little"),
        int.from_bytes(key[8:12], "little"),
        int.from_bytes(key[12:16], "little"),
        int.from_bytes(key[16:20], "little"),
        int.from_bytes(key[20:24], "little"),
        int.from_bytes(key[24:28], "little"),
        int.from_bytes(key[28:32], "little"),
        counter & 0xffffffff,
        int.from_bytes(nonce[0:4], "little"),
        int.from_bytes(nonce[4:8], "little"),
        int.from_bytes(nonce[8:12], "little")
    ]
    initial_state = list(state)
    
    for _ in range(10):
        chacha20_quarter_round(state, 0, 4, 8, 12)
        chacha20_quarter_round(state, 1, 5, 9, 13)
        chacha20_quarter_round(state, 2, 6, 10, 14)
        chacha20_quarter_round(state, 3, 7, 11, 15)
        chacha20_quarter_round(state, 0, 5, 10, 15)
        chacha20_quarter_round(state, 1, 6, 11, 12)
        chacha20_quarter_round(state, 2, 7, 8, 13)
        chacha20_quarter_round(state, 3, 4, 9, 14)
        
    output = []
    for i in range(16):
        output.append(((state[i] + initial_state[i]) & 0xffffffff).to_bytes(4, "little"))
    return b"".join(output)

def chacha20_encrypt(plaintext: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
    if len(key) != 32:
        raise ValueError("La clé ChaCha20 doit faire exactement 32 octets (256 bits).")
    if len(nonce) != 12:
        raise ValueError("Le nonce ChaCha20 doit faire exactement 12 octets (96 bits).")
        
    ciphertext = bytearray()
    counter = initial_counter
    
    for i in range(0, len(plaintext), 64):
        key_stream = chacha20_block(key, counter, nonce)
        block = plaintext[i:i+64]
        for b, k in zip(block, key_stream):
            ciphertext.append(b ^ k)
        counter += 1
    return bytes(ciphertext)

def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
    return chacha20_encrypt(ciphertext, key, nonce, initial_counter)


# =====================================================================
# 3. ELLIPTIC CURVE CRYPTOGRAPHY (ECC) NIST P-256
# =====================================================================
P_256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P_256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P_256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P_256_Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037d812deb33a0f4a13945d898c296
P_256_Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P_256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def mod_inverse(a: int, m: int) -> int:
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        high = low
        hm = lm
        low = new
        lm = nm
    return lm % m

class ECCPoint:
    def __init__(self, x: int, y: int, is_infinity: bool = False):
        self.x = x
        self.y = y
        self.is_infinity = is_infinity

    def __eq__(self, other):
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity != other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y

    def __str__(self):
        if self.is_infinity:
            return "Point à l'infini"
        return f"({hex(self.x)}, {hex(self.y)})"

G = ECCPoint(P_256_Gx, P_256_Gy)

def is_on_curve(p: ECCPoint) -> bool:
    if p.is_infinity:
        return True
    lhs = (p.y * p.y) % P_256_P
    rhs = (p.x * p.x * p.x + P_256_A * p.x + P_256_B) % P_256_P
    return lhs == rhs

def ecc_add(p1: ECCPoint, p2: ECCPoint) -> ECCPoint:
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    
    if p1.x == p2.x:
        if (p1.y + p2.y) % P_256_P == 0:
            return ECCPoint(0, 0, is_infinity=True)
        return ecc_double(p1)
        
    dy = (p2.y - p1.y) % P_256_P
    dx = (p2.x - p1.x) % P_256_P
    m = (dy * mod_inverse(dx, P_256_P)) % P_256_P
    
    x3 = (m*m - p1.x - p2.x) % P_256_P
    y3 = (m * (p1.x - x3) - p1.y) % P_256_P
    return ECCPoint(x3, y3)

def ecc_double(p: ECCPoint) -> ECCPoint:
    if p.is_infinity or p.y == 0:
        return ECCPoint(0, 0, is_infinity=True)
        
    dy = (3 * p.x * p.x + P_256_A) % P_256_P
    dx = (2 * p.y) % P_256_P
    m = (dy * mod_inverse(dx, P_256_P)) % P_256_P
    
    x3 = (m*m - 2 * p.x) % P_256_P
    y3 = (m * (p.x - x3) - p.y) % P_256_P
    return ECCPoint(x3, y3)

def ecc_mult(k: int, p: ECCPoint) -> ECCPoint:
    k = k % P_256_N
    result = ECCPoint(0, 0, is_infinity=True)
    addend = p
    
    while k > 0:
        if k & 1:
            result = ecc_add(result, addend)
        addend = ecc_double(addend)
        k >>= 1
    return result


# =====================================================================
# 4. SIGNATURES ECDSA
# =====================================================================
def ecdsa_sign(message: bytes, private_key: int) -> tuple:
    h = hashlib.sha256(message).digest()
    z = int.from_bytes(h, "big")
    
    while True:
        k = int.from_bytes(os.urandom(32), "big") % P_256_N
        if k == 0:
            continue
        r_point = ecc_mult(k, G)
        if r_point.is_infinity:
            continue
        r = r_point.x % P_256_N
        if r == 0:
            continue
        k_inv = mod_inverse(k, P_256_N)
        s = (k_inv * (z + r * private_key)) % P_256_N
        if s == 0:
            continue
        return r, s

def ecdsa_verify(message: bytes, signature: tuple, public_key: ECCPoint) -> bool:
    r, s = signature
    if not (0 < r < P_256_N and 0 < s < P_256_N):
        return False
        
    h = hashlib.sha256(message).digest()
    z = int.from_bytes(h, "big")
    
    w = mod_inverse(s, P_256_N)
    u1 = (z * w) % P_256_N
    u2 = (r * w) % P_256_N
    
    p1 = ecc_mult(u1, G)
    p2 = ecc_mult(u2, public_key)
    res_point = ecc_add(p1, p2)
    
    if res_point.is_infinity:
        return False
    return (res_point.x % P_256_N) == r


# =====================================================================
# 5. SÉRIALISATION & EXPORT (FORMAT "PEM" PERSONNALISÉ SANS BIBLIOTHÈQUES)
# =====================================================================
def serialize_custom_private_key(d: int, password: str = None) -> str:
    key_data = {}
    if password:
        salt = os.urandom(16)
        derived_key = pbkdf2_hmac_sha256(password.encode("utf-8"), salt, 2000, 32)
        nonce = os.urandom(12)
        plaintext = hex(d).encode("utf-8")
        ciphertext = chacha20_encrypt(plaintext, derived_key, nonce)
        key_data = {
            "encrypted": True,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }
    else:
        key_data = {
            "encrypted": False,
            "d": hex(d)
        }
    pem_body = json.dumps(key_data, indent=2)
    return f"-----BEGIN CUSTOM ECC PRIVATE KEY-----\n{pem_body}\n-----END CUSTOM ECC PRIVATE KEY-----"

def deserialize_custom_private_key(pem_str: str, password: str = None) -> int:
    try:
        lines = pem_str.strip().split("\n")
        body_lines = [l for l in lines if not l.startswith("-----")]
        body_json = "".join(body_lines)
        key_data = json.loads(body_json)
        
        if key_data.get("encrypted"):
            if not password:
                raise ValueError("La clé est chiffrée. Un mot de passe est obligatoire.")
            salt = bytes.fromhex(key_data["salt"])
            nonce = bytes.fromhex(key_data["nonce"])
            ciphertext = bytes.fromhex(key_data["ciphertext"])
            
            derived_key = pbkdf2_hmac_sha256(password.encode("utf-8"), salt, 2000, 32)
            plaintext = chacha20_decrypt(ciphertext, derived_key, nonce)
            d_str = plaintext.decode("utf-8")
            return int(d_str, 16)
        else:
            return int(key_data["d"], 16)
    except Exception as e:
        raise ValueError(f"Erreur de lecture de la clé privée : {e}")

def serialize_custom_public_key(point: ECCPoint) -> str:
    key_data = {
        "x": hex(point.x),
        "y": hex(point.y)
    }
    pem_body = json.dumps(key_data, indent=2)
    return f"-----BEGIN CUSTOM ECC PUBLIC KEY-----\n{pem_body}\n-----END CUSTOM ECC PUBLIC KEY-----"

def deserialize_custom_public_key(pem_str: str) -> ECCPoint:
    try:
        lines = pem_str.strip().split("\n")
        body_lines = [l for l in lines if not l.startswith("-----")]
        body_json = "".join(body_lines)
        key_data = json.loads(body_json)
        return ECCPoint(int(key_data["x"], 16), int(key_data["y"], 16))
    except Exception as e:
        raise ValueError(f"Erreur de lecture de la clé publique : {e}")

def create_custom_certificate(subject_cn: str, issuer_cn: str, validity_days: int, public_key: ECCPoint, issuer_private_key: int) -> str:
    cert_data = {
        "subject": {
            "CN": subject_cn
        },
        "issuer": {
            "CN": issuer_cn
        },
        "validity": {
            "days": validity_days
        },
        "public_key": {
            "x": hex(public_key.x),
            "y": hex(public_key.y)
        }
    }
    to_sign = json.dumps(cert_data, sort_keys=True).encode("utf-8")
    r, s = ecdsa_sign(to_sign, issuer_private_key)
    cert_data["signature"] = {
        "r": hex(r),
        "s": hex(s)
    }
    pem_body = json.dumps(cert_data, indent=2)
    return f"-----BEGIN CUSTOM SECURITY CERTIFICATE-----\n{pem_body}\n-----END CUSTOM SECURITY CERTIFICATE-----"

def verify_custom_certificate(cert_pem: str, issuer_public_key: ECCPoint) -> bool:
    try:
        lines = cert_pem.strip().split("\n")
        body_lines = [l for l in lines if not l.startswith("-----")]
        body_json = "".join(body_lines)
        cert_data = json.loads(body_json)
        
        sig_data = cert_data.pop("signature")
        r = int(sig_data["r"], 16)
        s = int(sig_data["s"], 16)
        
        to_verify = json.dumps(cert_data, sort_keys=True).encode("utf-8")
        return ecdsa_verify(to_verify, (r, s), issuer_public_key)
    except Exception:
        return False
