#!/usr/bin/env python
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import openssl

def build_ecdsa_pubkey(qx_bytes, qy_bytes):
    """Build ecdsa public key from provided curve point. Returns an
    EllipticCurvePublicKey object. Point must be specified by qx and qy
    values in little-endian byte order. Curve defaults to NIST-P384.
    See: AMD SEV API ver. 0.22 Chapter 4.5 and Appendix C.2"""
    pubkey_qx = int.from_bytes(qx_bytes, 'little')
    pubkey_qy = int.from_bytes(qy_bytes, 'little')

    curve = ec.SECP384R1()  # NIST-P384
    pub_numbers = ec.EllipticCurvePublicNumbers(pubkey_qx, pubkey_qy, curve)

    ec_pubkey = pub_numbers.public_key(openssl.backend)

    return ec_pubkey

def build_rsa_pubkey(pubkey_bytes):
    """Build RSA public_key from provided raw bytes. Returns a RSAPublicKey
    object. Key size defaults to 2048 bit. The key is expected to be in the
    Format as specified in AMD SEV API v22 Appendix B.1"""

    mod_len = e_len = 2048 // 8  # 0x100 bytes
    e = int.from_bytes(pubkey_bytes[0x40:0x40+e_len], 'little')
    modulus = int.from_bytes(pubkey_bytes[0x40+e_len:0x40+e_len+mod_len],
                             'little')

    pub_numbers = rsa.RSAPublicNumbers(e, modulus)

    return pub_numbers.public_key(openssl.backend)

def swap_sig_bytes(sig):
    """Converts a 2048 bit value to little endian."""
    sig_int = int.from_bytes(sig, 'little')
    return (sig_int).to_bytes(0x100, 'big')

# Read ASK and ARK for Epyc Naples
with open(sys.argv[1], 'rb') as f:
    ask_ark_naples = bytearray(f.read())

# Read the signed CEK public key
with open(sys.argv[2], 'rb') as f:
    cek = bytearray(f.read())


# Build the ASK RSAPublicKey object.
ask_pub = build_rsa_pubkey(ask_ark_naples[:0x240])

# Get the raw bytes to verify the authenticity of the ASK.
ask_raw = ask_ark_naples[:0x240]

# Get the ASK signature
ask_sig = swap_sig_bytes(ask_ark_naples[0x240:0x340])

# Build the ARK RSAPublicKey object.
ark_pub = build_rsa_pubkey(ask_ark_naples[0x340:])

# Build the CEK EllipticCurvePublicKey object.
# See AMD SEV API v0.22 Appendix C.1 and C.3.2
cek_pub = build_ecdsa_pubkey(cek[0x14:0x14+0x48], cek[0x5c:0x5c+0x48])

# Get the CEK signature.
cek_sig = swap_sig_bytes(cek[0x41c:0x51c])

# Get the raw bytes to verify the authenticity of the CEK.
cek_raw = cek[:0x414]


# Convert the public keys to pem format for openssl
ask_pem = ask_pub.public_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PublicFormat.SubjectPublicKeyInfo)

ark_pem = ark_pub.public_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PublicFormat.SubjectPublicKeyInfo)

cek_pem = cek_pub.public_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Store the keys and signatures
with open("./ask.pem", 'wb') as f:
    f.write(ask_pem)

with open("./ask.raw", 'wb') as f:
    f.write(ask_raw)

with open("./ask.sig", 'wb') as f:
    f.write(ask_sig)

with open("./ark.pem", 'wb') as f:
    f.write(ark_pem)

with open("./cek.pem", 'wb') as f:
    f.write(cek_pem)

with open("./cek.raw", 'wb') as f:
    f.write(cek_raw)

with open("./cek.sig", 'wb') as f:
    f.write(cek_sig)
