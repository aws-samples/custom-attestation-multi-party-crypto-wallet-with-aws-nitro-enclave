#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import logging
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..src.crypto.recovery_key import (decrypt_shard_via_recovery_public_key,
                                       encrypt_shard_via_recovery_public_key)

logger = logging.getLogger()
logger.level = logging.DEBUG
logger.addHandler(logging.StreamHandler(sys.stdout))


class TestEncryptDecryptShard(unittest.TestCase):
    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        self.public_key_b64 = base64.standard_b64encode(
            self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("utf-8")
        self.private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.shard = b"This is a test shard"

    def test_encrypt_shard(self):
        (
            encrypted_data_b64,
            ephemeral_public_key_b64,
        ) = encrypt_shard_via_recovery_public_key(self.public_key_b64, self.shard)

        self.assertEqual(len(encrypted_data_b64), 64)

    def test_decrypt_shard(self):
        (
            encrypted_data_b64,
            ephemeral_public_key_b64,
        ) = encrypt_shard_via_recovery_public_key(self.public_key_b64, self.shard)

        # Decrypt the encrypted data using the private key
        decrypted_data = decrypt_shard_via_recovery_public_key(
            encrypted_data_b64, self.private_key_pem, ephemeral_public_key_b64
        )

        # Verify the decrypted data
        self.assertEqual(base64.standard_b64decode(decrypted_data), self.shard)


# todo patch function - inject static private key
@unittest.skip("needs static private key injection")
class TestEncryptShardViaRecoveryPublicKey(unittest.TestCase):
    def setUp(self):
        self.public_key = ec.generate_private_key(ec.SECP384R1()).public_key()
        self.public_key_b64 = base64.standard_b64encode(
            self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("utf-8")
        self.shard = b"This is a test shard"

    @patch("os.urandom")
    def test_encrypt_shard_via_recovery_public_key(self, mock_urandom):
        mock_urandom.return_value = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"

        (
            encrypted_data_b64,
            ephemeral_public_key_b64,
        ) = encrypt_shard_via_recovery_public_key(self.public_key_b64, self.shard)

        # Verify the encrypted data and ephemeral public key
        self.assertEqual(
            encrypted_data_b64,
            "AQIDBAUGBwgJCgsM7n1pcm1kE0AbeL90aP1mV1OibA0XHkal9vRbma94itG98Q/U",
        )
        self.assertEqual(
            ephemeral_public_key_b64,
            "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFVXlGMlVxTVNhTmhyZTVhbkZBUkdNMkRXMkJwTwpUMjVVRmFBVXZMbUVMRWFQSFVNVTNxMXRHcXNnbFZMbGVZNWJNNGZYTkVQcGtWbVhZVnRRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t",
        )


@unittest.skip("needs static private key injection")
class TestDecryptShardViaRecoveryPublicKey(unittest.TestCase):
    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        self.private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.shard = b"This is a test shard"
        (
            self.encrypted_shard,
            self.ephemeral_public_key,
        ) = encrypt_shard_via_recovery_public_key(
            base64.standard_b64encode(self.public_key_pem).decode("utf-8"), self.shard
        )

    def test_decrypt_shard_via_recovery_public_key(self):
        decrypted_shard = decrypt_shard_via_recovery_public_key(
            base64.standard_b64encode(self.encrypted_shard).decode("utf-8"),
            base64.standard_b64encode(self.private_key_pem).decode("utf-8"),
            base64.standard_b64encode(self.ephemeral_public_key).decode("utf-8"),
        )
        self.assertEqual(decrypted_shard, base64.standard_b64encode(self.shard))


if __name__ == "__main__":
    unittest.main()
