#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
from functools import lru_cache

import boto3


@lru_cache(maxsize=1)
def get_ssm_parameters(session: boto3.Session, deployment: str) -> dict:
    ssm_client = session.client("ssm")
    try:
        response = ssm_client.get_parameters(
            Names=[
                f"/{deployment}/NitroWalletSSS/ShardsTableName",
                f"/{deployment}/NitroWalletSSS/KMSKeyID",
            ],
            WithDecryption=False,
        )
        logging.warning(f"[py] ssm parameter refresh: {response}")
    except Exception as e:
        logging.error(f"exception happened fetching parameter: {e}")
        raise e

    parameters = {
        param["Name"].split("/")[-1]: param["Value"] for param in response["Parameters"]
    }

    return parameters
