#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging

import requests

from ..config import NITRIDING_TIMEOUT


def signal_ready(nitriding_url: str) -> None:
    r = requests.get(nitriding_url + "/ready", timeout=NITRIDING_TIMEOUT)
    if r.status_code != 200:
        raise Exception(
            f"Expected status code {requests.codes.ok} but got {r.status_code}"
        )

    logging.info("[py] signaled ready to nitriding")


def provide_pk_hash(nitriding_url: str, pk_hash: bytes) -> None:
    r = requests.post(nitriding_url + "/hash", data=pk_hash, timeout=NITRIDING_TIMEOUT)

    if r.status_code != 200:
        raise Exception(
            f"Expected status code {requests.codes.ok} but got {r.status_code}"
        )

    logging.info("[py] Provided public key hash to nitriding")
