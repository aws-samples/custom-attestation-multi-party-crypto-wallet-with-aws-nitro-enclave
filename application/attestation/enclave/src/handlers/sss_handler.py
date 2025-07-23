#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import json
import logging
from http.server import BaseHTTPRequestHandler

import boto3

from ..aws.imds import resolve_credentials
from ..aws.kms import (KMSAccessDeniedException,
                       decrypt_shard_via_kms_cryptographic_attestation,
                       encrypt_shard_via_kms)
from ..aws.persistency import load_encrypted_shard, store_encrypted_shard
from ..config import PRIVATE_KEY_FILE, PUBLIC_KEY_FILE
from ..crypto.recovery_key import encrypt_shard_via_recovery_public_key
from ..crypto.shamir import (combine_shards_and_sign,
                             generate_and_split_private_key)


class SSSHandler(BaseHTTPRequestHandler):
    def _set_response(self, error_code: int):
        self.send_response(error_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def do_GET(self):
        if self.path == "/app/pk":
            with open(PUBLIC_KEY_FILE, "rb") as f:
                public_key = f.read()
            self._set_response(200)
            self.wfile.write(
                json.dumps(
                    {
                        "public_key": base64.standard_b64encode(public_key).decode(
                            "utf-8"
                        )
                    }
                ).encode("utf-8")
            )
            return

        self._set_response(200)
        self.wfile.write("GET request for {}".format(self.path).encode("utf-8"))

    def do_POST(self):
        if self.path == "/app/sss/key":
            try:
                # recovery_key
                if self.headers["Content-Length"] == 0:
                    self._set_response(400)
                    self.wfile.write(
                        json.dumps(
                            {
                                "error": "request requires recovery_public_key_b64 in json encoded body"
                            }
                        ).encode("utf-8")
                    )
                    return

                recovery_public_key_b64 = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )["recovery_public_key_b64"]
                logging.debug(
                    f"received recovery_public_key_b64: {recovery_public_key_b64}"
                )
                key_shard = generate_and_store_sss_pk(recovery_public_key_b64)
            except Exception as e:
                self._set_response(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
                return

            self._set_response(200)
            self.wfile.write(json.dumps(key_shard).encode("utf-8"))
            return

        if self.path == "/app/sss/signature":
            try:
                if self.headers["Content-Length"] == 0:
                    self._set_response(400)
                    self.wfile.write(
                        json.dumps(
                            {"error": "request requires json encoded body"}
                        ).encode("utf-8")
                    )
                    return

                params = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )

                # todo request validation
                key_shard_b64 = params["key_shard_b64"]
                pub_key = params["pub_key"]
                tx_hash = params["tx_hash"]

                signature = sign_transaction(key_shard_b64, pub_key, tx_hash)

            except KMSAccessDeniedException as e:
                self._set_response(403)
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
                return

            except Exception as e:
                self._set_response(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
                return

            self._set_response(200)
            self.wfile.write(json.dumps(signature).encode("utf-8"))
            return

        self._set_response(200)
        self.wfile.write("POST request for {}".format(self.path).encode("utf-8"))


@resolve_credentials
def generate_and_store_sss_pk(
    session: boto3.Session, ssm_params: dict, recovery_public_key_b64: str
) -> dict:
    """
    Generate a private key, split it into shards using Shamir's Secret Sharing, and store the shards securely.

    This function implements a 2-out-of-3 Shamir's Secret Sharing (SSS) scheme. It generates a private key,
    splits it into three shards, and processes each shard differently:

    1. Enclave Shard: Encrypted via KMS symmetric key and accessible via cryptographic attestation.
    2. User Shard: Returned in plaintext, protected by the TLS session.
    3. Recovery Shard: Encrypted with the provided EC public key.

    Args:
        session (boto3.Session): The boto3 session to use for AWS service interactions.
        ssm_params (dict): A dictionary containing necessary SSM parameters.
        recovery_public_key_b64 (str): Base64 encoded EC public key for encrypting the recovery shard.

    Returns:
        dict: A dictionary containing:
            - 'key_shard': Base64 encoded user shard (plaintext).
            - Other relevant data (public key, encrypted recovery shard, etc.).

    Raises:
        Exception: If encryption with KMS fails, storing in DynamoDB fails, or recovery shard encryption fails.

    Note:
        - This function assumes a 2-out-of-3 schema.
        - Proper error handling and logging are implemented for critical operations.
        - The function interacts with KMS for encryption and DynamoDB for storage.

    Process:
        1. Generate and split the private key into three shards.
        2. Encrypt the first shard (enclave shard) using KMS.
        3. Store the encrypted enclave shard and public key in DynamoDB.
        4. Encrypt the third shard (recovery shard) with the provided public key.
        5. Return the second shard (user shard) in plaintext, along with other relevant data.
    """

    shards, public_key = generate_and_split_private_key(3, 2)

    # encrypt key shard with KMS key returns b64 encoded ciphertext
    try:
        encrypted_shared = encrypt_shard_via_kms(session, ssm_params, shards[0])
    except Exception as e:
        logging.error(f"failed to encrypt key shard with KMS: {e}")
        return {}

    # store key shard + public key (key id) in dynamodb
    try:
        store_encrypted_shard(session, ssm_params, encrypted_shared, public_key.hex())
    except Exception as e:
        logging.error(f"failed to store key shard in ddb: {e}")
        return {}

    # encrypt recovery key shard with public key
    try:
        recovery_shard, ephemeral_public_key = encrypt_shard_via_recovery_public_key(
            public_key_b64=recovery_public_key_b64, shard=shards[2]
        )
    except Exception as e:
        logging.error(f"failed to encrypt recovery key shard with public key: {e}")
        return {}

    return {
        "key_shard": base64.standard_b64encode(shards[1]).decode("utf-8"),
        "public_key": public_key.hex(),
        "recovery": {
            "shard": recovery_shard,
            "ephemeral_public_key": ephemeral_public_key,
        },
    }


@resolve_credentials
def sign_transaction(
    session: boto3.Session,
    ssm_params: dict,
    key_shard_b64: str,
    pub_key: str,
    tx_hash: str,
) -> dict:
    """
    Sign a transaction using a distributed key shard system.

    This function implements a secure transaction signing process using a distributed key shard system.
    It retrieves the necessary key shards, assembles the complete key, and signs the provided transaction hash.

    Args:
        session (boto3.Session): The boto3 session to use for AWS service interactions.
        ssm_params (dict): A dictionary containing necessary SSM parameters.
        key_shard_b64 (str): Base64 encoded user key shard.
        pub_key (str): The public key associated with the transaction.
        tx_hash (str): The hash of the transaction to be signed.

    Returns:
        dict: A dictionary containing:
            - 'signature': The signature of the transaction hash.

    Returns:
        dict: An empty dictionary if any critical operation fails.

    Raises:
        Exception: If loading the encrypted shard fails.
        KMSAccessDeniedException: If permission is denied to decrypt the enclave key shard.
        Exception: If decryption of the enclave key shard fails.

    Note:
        - This function assumes a multi-party computation setup for transaction signing.
        - It interacts with DynamoDB to retrieve the encrypted shard and uses KMS for decryption.
        - Proper error handling and logging are implemented for critical operations.

    Process:
        1. Load the encrypted shard from DynamoDB using the provided public key.
        2. Decrypt the enclave key shard using KMS with Cryptographic Attestation.
        3. Decode the user-provided key shard.
        4. Assemble the complete key and validate it against the provided public key.
        5. Sign the provided transaction hash using the assembled key.
    """

    try:
        encrypted_shard = load_encrypted_shard(session, ssm_params, pub_key)
        logging.debug(f"got encrypted shard: {encrypted_shard}")
    except Exception as e:
        logging.error(f"failed to load encrypted shard: {e}")
        return {}

    try:
        key_shard_enclave_b64 = decrypt_shard_via_kms_cryptographic_attestation(
            session, ssm_params, PUBLIC_KEY_FILE, PRIVATE_KEY_FILE, encrypted_shard
        )
        logging.debug(f"got enclave key shard: {key_shard_enclave_b64}")

    except KMSAccessDeniedException as e:
        logging.error(f"permission denied to decrypt enclave key shard: {e}")
        raise e
    except Exception as e:
        logging.error(f"failed to decrypt enclave key shard: {e}")
        raise e

    try:
        key_shard_user = base64.standard_b64decode(key_shard_b64)
        key_shard_enclave = base64.standard_b64decode(key_shard_enclave_b64)
        signature, public_key = combine_shards_and_sign(
            [key_shard_enclave, key_shard_user], tx_hash.encode("utf-8")
        )
    except Exception as e:
        logging.error(f"failed to combine shards and sign: {e}")
        return {}

    if public_key.hex() != pub_key:
        logging.error(f"public key mismatch: {public_key.hex()} != {pub_key}")
        return {}

    return {"signature": base64.standard_b64encode(signature).decode("utf-8")}
