#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import hashlib
import logging
from typing import Tuple

import aws_nsm_interface_verifiably

from ..config import BLOCKSIZE


# todo wrap nsm handling in annotations
def get_attestation_doc(public_key_file: str) -> str:
    with open(public_key_file, "rb") as f:
        public_key_raw = f.read()

    file_desc = aws_nsm_interface_verifiably.open_nsm_device()

    attestation_doc = aws_nsm_interface_verifiably.get_attestation_doc(
        file_desc, public_key=public_key_raw
    )["document"]

    attestation_doc_b64 = base64.b64encode(attestation_doc).decode("utf-8")

    logging.debug(
        f"describe_nsm output: {aws_nsm_interface_verifiably.describe_nsm(file_desc)}"
    )

    aws_nsm_interface_verifiably.close_nsm_device(file_desc)

    return attestation_doc_b64


# todo wrap nsm handling in annotations
def extend_pcr(index: int, data: bytes) -> Tuple[bool, dict]:
    file_desc = aws_nsm_interface_verifiably.open_nsm_device()
    # https://lore.kernel.org/lkml/20231010213420.93725-1-graf@amazon.com/
    # write in 4kb (4096) blocks
    pcr_data = aws_nsm_interface_verifiably.extend_pcr(file_desc, index, data)

    pcr_lock = aws_nsm_interface_verifiably.lock_pcr(file_desc, index)

    logging.debug(
        f"describe_nsm output after extending and locking pcr {index}: {aws_nsm_interface_verifiably.describe_nsm(file_desc)}"
    )

    aws_nsm_interface_verifiably.close_nsm_device(file_desc)

    return pcr_lock, pcr_data


def extend_pcr_file(index: int, file: str) -> Tuple[bool, dict]:
    file_desc = aws_nsm_interface_verifiably.open_nsm_device()
    # https://lore.kernel.org/lkml/20231010213420.93725-1-graf@amazon.com/
    # write in 4kb (4096) blocks
    with open(file, "rb") as f:
        # 4096 request too large
        data = f.read(BLOCKSIZE)

        while len(data) > 0:
            pcr_data = aws_nsm_interface_verifiably.extend_pcr(file_desc, index, data)
            data = f.read(BLOCKSIZE)

    pcr_lock = aws_nsm_interface_verifiably.lock_pcr(file_desc, index)

    logging.debug(
        f"describe_nsm output after extending and locking pcr {index}: {aws_nsm_interface_verifiably.describe_nsm(file_desc)}"
    )

    aws_nsm_interface_verifiably.close_nsm_device(file_desc)

    return pcr_lock, pcr_data


def compute_pcr_file_hash(file_path, algorithm="sha384") -> str:
    hash_func = hashlib.new(algorithm)
    current_pcr = bytes(hash_func.digest_size)
    initial = True
    with open(file_path, "rb") as file:
        block = file.read(BLOCKSIZE)
        while len(block) > 0:
            if initial:
                hash_func.update(bytes(hash_func.digest_size) + block)
                current_pcr = hash_func.digest()

                initial = False

            else:
                hash_func.update(current_pcr + block)
                current_pcr = hash_func.digest()

            block = file.read(BLOCKSIZE)

    return current_pcr.hex()
