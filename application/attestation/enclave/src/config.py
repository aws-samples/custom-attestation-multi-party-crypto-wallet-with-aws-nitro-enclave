#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

NITRIDING_URL = "http://127.0.0.1:8080/enclave"
NITRIDING_TIMEOUT = 0.5
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
METADATA_SERVICE_ENDPOINT = "127.0.0.1"
METADATA_SERVICE_TIMEOUT = 1
TOKEN_TTL = 21600
TOKEN_URL = f"{METADATA_SERVICE_ENDPOINT}/latest/api/token"
ROLE_URL = f"{METADATA_SERVICE_ENDPOINT}/latest/meta-data/iam/security-credentials/"
BLOCKSIZE = 2048
CREDENTIALS_TTL_SECONDS = 3600
