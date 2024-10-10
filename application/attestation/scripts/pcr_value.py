#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import hashlib
import sys

BLOCKSIZE = 2048


# todo length should depend on selected hasher
def compute_pcr_file_hash(file_path, algorithm="sha384"):
    current_pcr = bytes(48)
    initial = True
    with open(file_path, "rb") as file:
        block = file.read(BLOCKSIZE)
        while len(block) > 0:
            hash_func = hashlib.new(algorithm)

            if initial:
                hash_func.update(bytes(48))
                hash_func.update(block)
                current_pcr = hash_func.digest()

                initial = False

            else:
                # print(f"1. current digest: {current_pcr.hex()}")
                hash_func.update(current_pcr)
                # print(f"2. new digest: {hash_func.digest().hex()}")
                hash_func.update(block)
                current_pcr = hash_func.digest()

            block = file.read(BLOCKSIZE)

    return current_pcr.hex()


if __name__ == "__main__":
    n = len(sys.argv)
    if n != 2:
        print("Usage: python3 pcr_value.py <file_path>")
        sys.exit(1)

    # print the new PCR value in hexadecimal format for verification
    new_pcr_value_hex = compute_pcr_file_hash(sys.argv[1])
    print(f"PCR value blocksize: {BLOCKSIZE}")
    print(f"PCR value (hex): {new_pcr_value_hex}")
