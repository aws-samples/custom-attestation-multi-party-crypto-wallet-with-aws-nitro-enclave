#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import ctypes
import gc
import logging
import secrets
from typing import Any, List, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyshamir import combine, split

logging.getLogger()


def generate_and_split_private_key(num_shards: int, threshold: int) -> tuple[list, Any]:
    # Generate a random 32-byte private key
    private_key_bytes = secrets.token_bytes(32)

    # Split the private key into shards
    shards = split(private_key_bytes, num_shards, threshold)

    # Create a secp256k1 SigningKey object
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, byteorder="big"), ec.SECP256K1()
    )
    # Get the corresponding public key
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )

    return shards, public_key


def zero_memory(data):
    if isinstance(data, (bytes, bytearray, int, ec.EllipticCurvePrivateKey)):
        address = id(data)
        logging.debug(f"zeroing out ({type(data)}) at: {address}")
        if isinstance(data, (bytes, bytearray)):
            # zero out the memory
            ctypes.memset(address, 0, len(data))
        elif isinstance(data, int):
            # for integers, convert to bytes first
            byte_length = (data.bit_length() + 7) // 8
            data_bytes = data.to_bytes(byte_length, byteorder="big")
            zero_memory(data_bytes)
        elif isinstance(data, ec.EllipticCurvePrivateKey):
            # for private keys, attempt to zero out the private value
            private_numbers = data.private_numbers()
            try:
                private_value = private_numbers.private_value
                zero_memory(private_value)
                # set to zero after zeroing out
                private_numbers._private_value = 0
            except Exception:
                # if we can't zero it out, overwrite with random data
                key_size = data.key_size
                random_int = int.from_bytes(
                    secrets.token_bytes(key_size // 8), byteorder="big"
                )
                private_numbers._private_value = random_int


def combine_shards_and_sign(shards: List[bytes], message: bytes) -> Tuple[bytes, bytes]:
    private_key_bytes = None
    private_key = None
    try:
        # Combine the shards to reconstruct the private key
        private_key_bytes = combine(shards)

        # Create a secp256k1 SigningKey object
        private_key = ec.derive_private_key(
            int.from_bytes(private_key_bytes, byteorder="big"), ec.SECP256K1()
        )

        # Sign the message
        signature = private_key.sign(
            message, signature_algorithm=ec.ECDSA(hashes.SHA256())
        )

        # Get the public key
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        return signature, public_key

    finally:
        # zero out private_key_bytes
        if private_key_bytes:
            zero_memory(private_key_bytes)

        # zero out private_key
        if private_key:
            zero_memory(private_key)

        # remove references
        del private_key_bytes
        del private_key

        # force garbage collection
        gc.collect()
