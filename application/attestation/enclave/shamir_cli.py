#!/usr/bin/env python3

#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import argparse
import base64
import json
import logging
import sys

from src.aws.nsm import compute_pcr_file_hash
from src.config import BLOCKSIZE
from src.crypto.ec import convert_x962_to_der, verify_signature
from src.crypto.recovery_key import decrypt_shard_via_recovery_public_key
from src.crypto.shamir import combine_shards_and_sign

logger = logging.getLogger()
# changing logging to debug will interrupt stdout capturing in shell
logger.level = logging.WARNING
logger.addHandler(logging.StreamHandler(sys.stdout))


def decompress_x962_pub_key(args):
    with open(args.public_key_file, "rt") as f:
        compressed_key = f.read()

    decompressed_key_der = convert_x962_to_der(bytes.fromhex(compressed_key))

    print(
        json.dumps(
            {
                "decompressed_pub_key_der_b64": base64.standard_b64encode(
                    decompressed_key_der
                ).decode()
            }
        )
    )


def decrypt_message(args):
    with open(args.message_file, "rb") as f:
        encrypted_shard_b64 = f.read()

    with open(args.private_key_file, "rb") as f:
        private_key_raw = f.read()

    with open(args.ephemeral_public_key_file, "rb") as f:
        ephemeral_public_key_b64 = f.read()

    decrypted = decrypt_shard_via_recovery_public_key(
        encrypted_shard_b64=encrypted_shard_b64.decode(),
        private_key_raw=private_key_raw,
        ephemeral_public_key_b64=ephemeral_public_key_b64.decode(),
    )
    print(json.dumps({"decrypted_message": decrypted}))


def calculate_pcr_value(args):
    new_pcr_value_hex = compute_pcr_file_hash(args.file_path)
    print(
        json.dumps(
            {
                "blocksize": BLOCKSIZE,
                "hash_algorithm": "SHA-384",
                "pcr_value": new_pcr_value_hex,
            }
        )
    )


def _combine_shards_and_sign(args):
    shards = [
        base64.standard_b64decode(args.shard1),
        base64.standard_b64decode(args.shard2),
    ]
    hash_value = args.hash.encode()

    signature, public_key = combine_shards_and_sign(shards, hash_value)

    print(
        json.dumps(
            {
                "public_key": public_key.hex(),
                "signature": signature.hex(),
                "signature_b64": base64.standard_b64encode(signature).decode(),
                "hash_value_b64": base64.standard_b64encode(hash_value).decode(),
            }
        )
    )


def _verify_signature(args):
    public_key_der = base64.standard_b64decode(args.public_key_der_b64)
    signature = base64.standard_b64decode(args.signature_b64)
    hash_value = base64.standard_b64decode(args.hash_value_b64)

    is_valid = verify_signature(public_key_der, signature, hash_value)

    print(json.dumps({"is_valid": is_valid}))


def main():
    parser = argparse.ArgumentParser(description="Utility CLI")
    subparsers = parser.add_subparsers(dest="command")

    decompress_parser = subparsers.add_parser(
        "decompress", help="Decompress a serialized x962 pub key"
    )
    decompress_parser.add_argument(
        "public_key_file", type=str, help="Path to the compressed key file"
    )
    decompress_parser.set_defaults(func=decompress_x962_pub_key)

    verify_parser = subparsers.add_parser("verify", help="Validate a signature")
    verify_parser.add_argument(
        "signature_b64", type=str, help="Base64-encoded signature"
    )
    verify_parser.add_argument(
        "public_key_der_b64", type=str, help="Base64-encoded der public key"
    )
    verify_parser.add_argument(
        "hash_value_b64", type=str, help="Base64-encoded hash value"
    )
    verify_parser.set_defaults(func=_verify_signature)

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a message")
    decrypt_parser.add_argument(
        "message_file", type=str, help="Path to the encrypted message file"
    )
    decrypt_parser.add_argument(
        "private_key_file", type=str, help="Path to the private key file"
    )
    decrypt_parser.add_argument(
        "ephemeral_public_key_file",
        type=str,
        help="Path to the ephemeral public key file",
    )
    decrypt_parser.set_defaults(func=decrypt_message)

    pcr_parser = subparsers.add_parser("pcr", help="Calculate PCR value for a file")
    pcr_parser.add_argument("file_path", type=str, help="Path to the file")
    pcr_parser.set_defaults(func=calculate_pcr_value)

    combine_parser = subparsers.add_parser("combine", help="Combine shards and sign")
    combine_parser.add_argument("shard1", type=str, help="Base64-encoded shard 1")
    combine_parser.add_argument("shard2", type=str, help="Base64-encoded shard 2")
    combine_parser.add_argument("hash", type=str, help="Hash value")
    combine_parser.set_defaults(func=_combine_shards_and_sign)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
