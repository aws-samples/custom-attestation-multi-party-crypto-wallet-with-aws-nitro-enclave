#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import logging
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def encrypt_shard_via_recovery_public_key(
    public_key_b64: str, shard: bytes
) -> Tuple[str, str]:
    public_key = base64.standard_b64decode(public_key_b64)
    public_key_parsed = serialization.load_pem_public_key(public_key)

    ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # derive shared secret using ECDH
    # https://github.com/nakov/Practical-Cryptography-for-Developers-Book/blob/master/asymmetric-key-ciphers/ecc-encryption-decryption.md
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key_parsed)
    logging.debug(f"encrypt shared key: {shared_key.hex()}")

    # derive a symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)
    logging.debug(f"encrypt derived key: {derived_key.hex()}")

    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(derived_key), modes.GCM(iv)).encryptor()

    ciphertext = encryptor.update(shard) + encryptor.finalize()

    # combine IV, ciphertext, and tag (GCM)
    # iv 12 byte
    # tag 16 byte
    encrypted_data_b64 = base64.standard_b64encode(
        iv + ciphertext + encryptor.tag
    ).decode("utf-8")

    ephemeral_public_key_b64 = base64.standard_b64encode(
        ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("utf-8")

    return encrypted_data_b64, ephemeral_public_key_b64


def decrypt_shard_via_recovery_public_key(
    encrypted_shard_b64: str, private_key_raw: bytes, ephemeral_public_key_b64: str
) -> str:
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

    # Derive the symmetric key using HKDF
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

    return base64.standard_b64encode(decrypted_data).decode("utf-8")
