#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import hashlib
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def generate_ec_keys(
    private_key_file: str,
    public_key_file: str,
    key_type: str = "ec",
    encoding: str = "pem",
) -> bytes:
    if key_type == "ec":
        # Generate a private key
        private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP256R1()
        )

        # Derive the public key from the private key
        public_key: ec.EllipticCurvePublicKey = private_key.public_key()

    elif key_type == "rsa":
        private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key: rsa.RSAPublicKey = private_key.public_key()

    else:
        raise Exception("Unsupported key type")

    if encoding == "pem":
        encoding = serialization.Encoding.PEM
    elif encoding == "der":
        encoding = serialization.Encoding.DER
    else:
        raise Exception("Unsupported encoding")

    # Serialize the private key to PEM format
    private_key_pem: bytes = private_key.private_bytes(
        encoding=encoding,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize the public key to PEM format
    public_key_pem: bytes = public_key.public_bytes(
        encoding=encoding, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Calculate the SHA-256 hash of the public key
    public_key_hash: bytes = base64.standard_b64encode(
        hashlib.sha256(public_key_pem).digest()
    )

    # Write the private key to a file
    with open(private_key_file, "wb") as f:
        f.write(private_key_pem)

    # Write the public key to a file
    with open(public_key_file, "wb") as f:
        f.write(public_key_pem)

    logging.debug(f"Private key saved to: {private_key_file}")
    logging.debug(f"Public key saved to: {public_key_file}")

    return public_key_hash


def convert_x962_to_der(compressed_public_key: bytes) -> bytes:
    # determine the prefix to identify the compressed format
    prefix = compressed_public_key[0]
    logging.debug(f"Prefix: {prefix}")
    if prefix not in (0x02, 0x03):
        raise ValueError("Invalid compressed key format")

    # Extract the x-coordinate from the compressed key
    # x_coordinate = int.from_bytes(compressed_key[1:], byteorder='big')

    # Create an EC public key object using the x-coordinate
    curve = ec.SECP256K1()
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        curve, compressed_public_key
    )
    # public_key = public_numbers.public_key(default_backend())

    # Serialize the public key to DER format
    der_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return der_key


def verify_signature(public_key_der: bytes, signature: bytes, message: bytes) -> bool:
    # Load the public key
    public_key = serialization.load_der_public_key(
        public_key_der, backend=default_backend()
    )

    # Verify the signature
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False
