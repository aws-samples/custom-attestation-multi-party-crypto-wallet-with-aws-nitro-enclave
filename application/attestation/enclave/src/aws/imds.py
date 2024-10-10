#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os
import time
from functools import lru_cache

import boto3
import requests

from ..config import (CREDENTIALS_TTL_SECONDS, METADATA_SERVICE_TIMEOUT,
                      ROLE_URL, TOKEN_TTL, TOKEN_URL)
from .ssm import get_ssm_parameters


# temp credentials are valid for 6h (per default)
@lru_cache(maxsize=1)
def get_temp_credentials(ttl_hash=None) -> boto3.Session:
    del ttl_hash
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": str(TOKEN_TTL)}

    try:
        token = requests.put(
            url=f"http://{TOKEN_URL}", headers=headers, timeout=METADATA_SERVICE_TIMEOUT
        )
        token_header = {"X-aws-ec2-metadata-token": token.text}
        logging.warning(f"[py] cred token refresh: {token.text}")
    except Exception as e:
        logging.error(f"exception happened fetching token: {e}")
        raise e

    try:
        role = requests.get(
            url=f"http://{ROLE_URL}",
            headers=token_header,
            timeout=METADATA_SERVICE_TIMEOUT,
        )
        logging.debug(f"[py] role: {role.text}")
    except Exception as e:
        logging.error(f"exception happened fetching role: {e}")
        raise e

    try:
        creds = requests.get(
            url=f"http://{ROLE_URL}{role.text}",
            headers=token_header,
            timeout=METADATA_SERVICE_TIMEOUT,
        )  # nosec
        logging.debug(f"[py] creds: {creds.text}")
    except Exception as e:
        logging.error(f"exception happened fetching token: {e}")
        raise e

    creds_dct = creds.json()
    session = boto3.Session(
        region_name=os.getenv("REGION"),
        aws_access_key_id=creds_dct["AccessKeyId"],
        aws_secret_access_key=creds_dct["SecretAccessKey"],
        aws_session_token=creds_dct["Token"],
    )

    return session


def resolve_credentials(func):
    def get_ttl_hash(seconds=CREDENTIALS_TTL_SECONDS):
        return round(time.time() / seconds)

    def resolve_creds(*args, **kwargs):
        try:
            # todo return region from metadata service
            # leveraging lru_cache ttl_hash for expiration check
            session = get_temp_credentials(ttl_hash=get_ttl_hash())
        except Exception as e:
            logging.error(f"failed to get temp credentials: {e}")
            return {}

        try:
            ssm_params = get_ssm_parameters(session, os.getenv("DEPLOYMENT"))
        except Exception as e:
            logging.error(f"failed to get required info from ssm: {e}")
            return {}

        func(session, ssm_params, *args, **kwargs)

        return func(session, ssm_params, *args, **kwargs)

    return resolve_creds
