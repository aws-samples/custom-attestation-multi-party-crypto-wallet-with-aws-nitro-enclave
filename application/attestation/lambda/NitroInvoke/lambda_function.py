#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import json
import logging
import os
import ssl
from http import client

ssl_context = ssl.SSLContext()
ssl_context.verify_mode = ssl.CERT_NONE

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger("tx_manager_controller")
_logger.setLevel(LOG_LEVEL)
_logger.addHandler(handler)
_logger.propagate = False


def lambda_handler(event, context):
    """
    example requests
    {
      "operation": "GET",
      "transaction_payload": {
        "url": "url",
        "payload": "payload"
        }
    }

    """
    nitro_instance_private_dns = os.getenv("NITRO_INSTANCE_PRIVATE_DNS")

    if not (nitro_instance_private_dns):
        _logger.fatal("NITRO_INSTANCE_PRIVATE_DNS environment variables need to be set")

    operation = event.get("operation")
    if not operation:
        _logger.fatal("request needs to define operation such as GET or POST")

    transaction_payload = event.get("transaction_payload")
    if not transaction_payload:
        raise Exception("operation proxy requires transaction_payload")

    url = transaction_payload.get("url")
    if not url:
        raise Exception("operation proxy requires url in transaction_payload")

    https_nitro_client = client.HTTPSConnection(
        f"{nitro_instance_private_dns}:443", context=ssl_context, timeout=5
    )

    try:
        operation_upper = operation.upper()
        https_nitro_client.request(
            operation.upper(),
            url=url,
            # just set body and headers for non get requests
            body=(
                None
                if operation_upper == "GET"
                else json.dumps(transaction_payload.get("payload"))
            ),
            headers=(
                {} if operation_upper == "GET" else {"Content-Type": "application/json"}
            ),
        )
        response = https_nitro_client.getresponse()
    except Exception as e:
        raise Exception(
            f"exception happened sending {operation} request to Nitro Enclave: {e}"
        )

    _logger.debug(f"response: {response.status} {response.reason}")

    response_raw = response.read()

    _logger.debug(f"response data: {response_raw}")

    content_type = response.getheader("Content-Type")
    if content_type == "application/json":
        response_parsed = json.loads(response_raw)
    else:
        response_parsed = response_raw

    response.close()

    return response_parsed
