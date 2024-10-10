#!/usr/bin/env python3

#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import sys
from http.server import HTTPServer

from src.aws.nsm import compute_pcr_file_hash, extend_pcr_file
from src.config import NITRIDING_URL, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE
from src.crypto.ec import generate_ec_keys
from src.handlers.sss_handler import SSSHandler
from src.nitriding.requests import provide_pk_hash, signal_ready

logging.basicConfig(level=logging.INFO)


def run(server_class=HTTPServer, handler_class=SSSHandler, port=8088):
    logging.info("Starting httpd...\n")
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)
    logging.info(f"Running server on port {port}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info("Stopping httpd...\n")


if __name__ == "__main__":
    # generate pk and return hash
    try:
        pk_sha256 = generate_ec_keys(
            private_key_file=PRIVATE_KEY_FILE,
            public_key_file=PUBLIC_KEY_FILE,
            key_type="rsa",
            encoding="der",
        )
    except Exception as e:
        logging.error(f"exception happened generating keys: {e}")
        sys.exit(1)

    # submit hash of pk
    try:
        provide_pk_hash(NITRIDING_URL, pk_sha256)
    except Exception as e:
        logging.error(f"exception happened providing pk hash: {e}")
        sys.exit(1)

    # lock additional pcr value (16) using deterministic builds reflecting the sha384 PCR hash value
    try:
        proxy_sha384_hash = compute_pcr_file_hash("/app/proxy")
        logging.info(f"sha384 PCR hash of proxy binary: {proxy_sha384_hash}")
    except Exception as e:
        logging.error(f"exception happened computing pcr file hash: {e}")

    try:
        extend_status, extend_data = extend_pcr_file(16, "/app/proxy")
        logging.info(f"extend status: {extend_status} / extend data: {extend_data}")
    except Exception as e:
        logging.error(f"exception happened extending pcr: {e}")

    try:
        signal_ready(NITRIDING_URL)
    except Exception as e:
        logging.error(f"exception happened signaling ready: {e}")
        sys.exit(1)

    run()
