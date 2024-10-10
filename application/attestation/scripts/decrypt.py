#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import logging
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger()
logger.level = logging.DEBUG
logger.addHandler(logging.StreamHandler(sys.stdout))


# todo remove code duplicate, create proper package structure and refer to libs
def decrypt_shard_via_recovery_public_key(
    encrypted_shard_b64: bytes, private_key_raw: bytes, ephemeral_public_key_b64: bytes
):
    """Encrypts or decrypts a message using ECC and AES.

    For encryption: provide the message and public_key.
    For decryption: provide the encrypted message and private_key.

    Returns a tuple (ciphertext, ephemeral_public_key) for encryption,
    or the decrypted message for decryption.
    """

    encrypted_shard = base64.standard_b64decode(encrypted_shard_b64)

    loaded_private_key = serialization.load_pem_private_key(
        private_key_raw, password=None
    )

    ephemeral_public_key = base64.standard_b64decode(ephemeral_public_key_b64)
    loaded_ephemeral_public_key = serialization.load_pem_public_key(
        ephemeral_public_key
    )

    iv = encrypted_shard[:12]
    ciphertext = encrypted_shard[12:-16]
    tag = encrypted_shard[-16:]

    shared_key = loaded_private_key.exchange(ec.ECDH(), loaded_ephemeral_public_key)
    logging.debug(f"decrypt shared key: {shared_key.hex()}")

    # derive the symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)
    logging.debug(f"decrypt derived key: {derived_key.hex()}")

    # decrypt the message using AES-GCM
    decryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv, tag),
    ).decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return base64.standard_b64encode(decrypted_data)


if __name__ == "__main__":
    n = len(sys.argv)
    if n != 4:
        print(
            "Usage: decrypt.py <message_file> <private_key_file> <ephemeral_public_key_file>"
        )
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        encrypted_shard_b64 = f.read()

    with open(sys.argv[2], "rb") as f:
        private_key_raw = f.read()

    with open(sys.argv[3], "rb") as f:
        ephemeral_public_key_b64 = f.read()

    # decrypt the message
    decrypted = decrypt_shard_via_recovery_public_key(
        encrypted_shard_b64=encrypted_shard_b64.decode(),
        private_key_raw=private_key_raw,
        ephemeral_public_key_b64=ephemeral_public_key_b64.decode(),
    )
    print(f"decrypted: {decrypted}")
