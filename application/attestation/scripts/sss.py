#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import sys
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyshamir import combine


# todo remove code duplicate, create proper package structure and refer to libs
def combine_shards_and_sign(
    shards: List[bytearray], message: bytes
) -> Tuple[bytes, bytes]:
    # Combine the shards to reconstruct the private key
    private_key_bytes = combine(shards)

    # Create a secp256k1 SigningKey object
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, byteorder="big"), ec.SECP256K1()
    )

    signature = private_key.sign(message, signature_algorithm=ec.ECDSA(hashes.SHA256()))

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )

    return signature, public_key


if __name__ == "__main__":
    n = len(sys.argv)
    if n != 4:
        print("Usage: sss.py <shard1> <shard2> <hash>")
        sys.exit(1)

    # decrypt the message
    signature, public_key = combine_shards_and_sign(
        [
            base64.standard_b64decode(sys.argv[1]),
            base64.standard_b64decode(sys.argv[2]),
        ],
        sys.argv[3].encode(),
    )

    print(f"public_key: {public_key.hex()}")
    print(f"signature: {signature.hex()}")
