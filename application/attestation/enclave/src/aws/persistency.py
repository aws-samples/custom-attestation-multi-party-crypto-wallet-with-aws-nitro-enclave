#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging

import boto3


def store_encrypted_shard(
    session: boto3.Session, ssm_params: dict, encrypted_shard: str, public_key: str
):
    ddb_client = session.client("dynamodb")
    try:
        response = ddb_client.put_item(
            TableName=ssm_params["ShardsTableName"],
            Item={"PublicKey": {"S": public_key}, "Shard": {"S": encrypted_shard}},
        )
    except Exception as e:
        logging.error(f"exception happened storing encrypted shard: {e}")
        raise e

    return response


def load_encrypted_shard(
    session: boto3.Session, ssm_params: dict, public_key: str
) -> str:
    ddb_client = session.client("dynamodb")
    try:
        response = ddb_client.get_item(
            TableName=ssm_params["ShardsTableName"],
            Key={"PublicKey": {"S": public_key}},
        )
    except Exception as e:
        logging.error(f"exception happened loading encrypted shard: {e}")
        raise e

    if "Item" not in response:
        raise Exception("No shard found for the given public key")

    return response["Item"]["Shard"]["S"]
