#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import hashlib
import os

import pytest
from cryptography.hazmat.primitives import serialization

from ..src.crypto.ec import generate_ec_keys


def test_generate_ec_keys(tmp_path):
    # Arrange
    private_key_file = os.path.join(tmp_path, "private_key.pem")
    public_key_file = os.path.join(tmp_path, "public_key.pem")

    # Act
    public_key_hash = generate_ec_keys(private_key_file, public_key_file)

    # Assert
    assert public_key_hash is not None
    assert len(public_key_hash) == 44  # SHA-256 hash length is 64 characters

    # Verify that the private key file exists and is not empty
    assert os.path.isfile(private_key_file)
    assert os.path.getsize(private_key_file) > 0

    # Verify that the public key file exists and is not empty
    assert os.path.isfile(public_key_file)
    assert os.path.getsize(public_key_file) > 0

    # Load the private key from the file
    with open(private_key_file, "rb") as f:
        private_key_pem = f.read()
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=None
    )

    # Load the public key from the file
    with open(public_key_file, "rb") as f:
        public_key_raw = f.read()
    public_key_pem = serialization.load_pem_public_key(public_key_raw, backend=None)

    # Verify that the public key matches the private key
    assert private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == public_key_pem.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Verify that the public key hash matches the expected value
    expected_public_key_hash = hashlib.sha256(
        public_key_pem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).digest()
    print(base64.standard_b64encode(expected_public_key_hash))
    assert public_key_hash == base64.standard_b64encode(expected_public_key_hash)


def test_generate_ec_keys_invalid_file_path(tmp_path):
    # Arrange
    invalid_file_path = os.path.join(tmp_path, "invalid", "file.pem")

    # Act and Assert
    with pytest.raises(IOError):
        generate_ec_keys(invalid_file_path, invalid_file_path)
