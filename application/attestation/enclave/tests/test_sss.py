#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import sys
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pyshamir import combine

from ..src.crypto.shamir import (combine_shards_and_sign,
                                 generate_and_split_private_key)

logger = logging.getLogger()
logger.level = logging.DEBUG
logger.addHandler(logging.StreamHandler(sys.stdout))


class TestShamirSecretSharing(unittest.TestCase):
    def setUp(self):
        self.num_shards = 5
        self.threshold = 3
        self.message = b"Hello, World!"
        self.shards, self.public_key = generate_and_split_private_key(
            self.num_shards, self.threshold
        )

    def test_generate_and_split_private_key(self):
        # Test the number of shards generated
        self.assertEqual(len(self.shards), self.num_shards)

        # Test that each shard is a tuple of (int, bytes)
        for shard in self.shards:
            self.assertIsInstance(shard, bytearray)
            # self.assertIsInstance(shard[0], int)
            # self.assertIsInstance(shard[1], bytes)

        # Test the length of the public key
        self.assertEqual(len(self.public_key), 33)

    def test_combine_shards_and_sign(self):
        # Combine shards and sign the message
        signature, recovered_public_key = combine_shards_and_sign(
            self.shards[: self.threshold], self.message
        )

        # Test the length of the signature
        self.assertGreater(len(signature), 0)

        # Test the length of the recovered public key
        self.assertEqual(len(recovered_public_key), 33)

        # Verify the signature
        # verifying_key = SigningKey.from_string(
        #     combine(self.shards[: self.threshold]), curve=SECP256k1
        # ).verifying_key

        private_key = ec.derive_private_key(
            int.from_bytes(combine(self.shards[: self.threshold]), byteorder="big"),
            ec.SECP256K1(),
        )

        # signature = private_key.sign(message, signature_algorithm=ecdsa.SECP256k1)

        verifying_key = private_key.public_key()

        try:
            verifying_key.verify(
                signature, self.message, signature_algorithm=ec.ECDSA(hashes.SHA256())
            )
        except Exception as e:
            self.fail(f"Signature verification failed: {e}")


if __name__ == "__main__":
    unittest.main()
