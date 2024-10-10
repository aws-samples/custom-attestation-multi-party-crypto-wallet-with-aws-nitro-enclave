#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import logging

import boto3
from asn1crypto import cms
from botocore.exceptions import ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .nsm import get_attestation_doc


class KMSAccessDeniedException(Exception):
    def __init__(self, message):
        self.message = message


def decrypt_shard_via_kms_cryptographic_attestation(
    session: boto3.Session,
    ssm_params: dict,
    public_key_file: str,
    private_key_file: str,
    ciphertext_b64: str,
) -> str:
    try:
        attestation_doc_b64 = get_attestation_doc(public_key_file)
        logging.debug(f"attestation doc: {attestation_doc_b64}")
    except Exception as e:
        logging.error(f"exception happened fetching attestation doc: {e}")
        raise e

    try:
        ciphertext_for_recipient = decrypt_shard_via_kms_ca(
            session, ssm_params, ciphertext_b64, attestation_doc_b64
        )
        logging.debug(f"ciphertext for recipient: {ciphertext_for_recipient}")
    except Exception as e:
        logging.error(f"exception happened decrypting cms shard: {e}")
        raise e

    try:
        plaintext = decrypt_ciphertext_for_recipient(
            ciphertext_for_recipient, private_key_file
        )
        logging.debug(f"plaintext from recipient ciphertext: {plaintext}")
    except Exception as e:
        logging.error(f"exception happened decrypting ciphertext for recipient: {e}")
        raise e

    return plaintext


def decrypt_ciphertext_for_recipient(
    ciphertext_for_recipient_b64: str, private_key_file: str
) -> str:
    ciphertext_for_recipient = base64.b64decode(ciphertext_for_recipient_b64)
    with open(private_key_file, "rb") as f:
        private_key_raw = f.read()
        logging.debug(
            f"private key raw: {base64.b64encode(private_key_raw).decode('utf-8')}"
        )
    try:
        private_key = serialization.load_der_private_key(private_key_raw, password=None)
    except Exception as e:
        logging.error(f"exception happened loading private key: {e}")
        raise e

    content_info = cms.ContentInfo.load(ciphertext_for_recipient)
    enveloped_data = content_info["content"]
    recipient_infos = enveloped_data["recipient_infos"][0].chosen

    encrypted_key = recipient_infos["encrypted_key"].native
    logging.debug(f"cms encrypted symmetric key:{encrypted_key}")

    encrypted_content_info = enveloped_data["encrypted_content_info"]
    content_encryption_algorithm = encrypted_content_info[
        "content_encryption_algorithm"
    ]
    iv = content_encryption_algorithm["parameters"].native
    logging.debug(f"aes cbc iv: {iv}")

    encrypted_content = encrypted_content_info["encrypted_content"].native
    logging.debug(f"cms encrypted content: {encrypted_content}")

    # Decrypt the content using RSA-OAEP padding
    # https://docs.anjuna.io/nitro/latest/getting_started/how_to/attestation_endpoint_with_kms.html
    try:
        decrypted_sym_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        logging.error(f"exception happened decrypting AES sym key: {e}")
        raise e

    try:
        cipher = Cipher(
            algorithms.AES(decrypted_sym_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()
    except Exception as e:
        logging.error(
            f"exception happened decrypting encrypted content via AES sym key: {e}"
        )
        raise e

    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_content = unpadder.update(decrypted_padded) + unpadder.finalize()

    return base64.b64encode(decrypted_content).decode("utf-8")


def encrypt_shard_via_kms(
    session: boto3.Session, ssm_params: dict, shard: bytes
) -> str:
    kms_client = session.client("kms")
    try:
        response = kms_client.encrypt(
            # todo move to aws handler class
            KeyId=ssm_params["KMSKeyID"],
            Plaintext=shard,
        )
    except Exception as e:
        logging.error(f"exception happened encrypting shard: {e}")
        raise e

    ciphertext_blob_b64 = base64.standard_b64encode(response["CiphertextBlob"]).decode(
        "utf-8"
    )

    return ciphertext_blob_b64


def decrypt_shard_via_kms_ca(
    session: boto3.Session,
    ssm_params: dict,
    ciphertext_blob_b64: str,
    attestation_doc_b64: str,
) -> str:
    kms_client = session.client("kms")
    try:
        response = kms_client.decrypt(
            KeyId=ssm_params["KMSKeyID"],
            CiphertextBlob=base64.standard_b64decode(ciphertext_blob_b64),
            Recipient={
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "AttestationDocument": base64.standard_b64decode(attestation_doc_b64),
            },
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            raise KMSAccessDeniedException(f"Access denied by KMS: {e.response}")
        else:
            raise e

    return base64.standard_b64encode(response["CiphertextForRecipient"]).decode("utf-8")


def decrypt_shard_via_kms(
    session: boto3.Session, ssm_params: dict, ciphertext_blob_b64: str
) -> str:
    kms_client = session.client("kms")
    try:
        response = kms_client.decrypt(
            KeyId=ssm_params["KMSKeyID"],
            CiphertextBlob=base64.standard_b64decode(ciphertext_blob_b64),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            raise KMSAccessDeniedException(f"Access denied by KMS: {e.response}")
        else:
            raise e
    return base64.standard_b64encode(response["Plaintext"]).decode("utf-8")
