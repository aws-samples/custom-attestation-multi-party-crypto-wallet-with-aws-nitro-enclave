#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import json
import subprocess  # nosec B404
import time

ENCLAVE_NAME = "app"


def nitro_cli_describe_call(enclave_name: str = None) -> bool:
    subprocess_args = ["/bin/nitro-cli", "describe-enclaves"]

    print("enclave args: {}".format(subprocess_args))

    proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE)  # nosec B603

    nitro_cli_response = proc.communicate()[0].decode()

    if enclave_name:
        response = json.loads(nitro_cli_response)

        if len(response) != 1:
            return False

        if (
            response[0].get("EnclaveName") != enclave_name
            and response[0].get("State") != "Running"
        ):
            return False

    return True


def nitro_cli_run_call(enclave_name: str, debug_mode: bool = False) -> str:
    subprocess_args = [
        "/bin/nitro-cli",
        "run-enclave",
        "--cpu-count",
        "2",
        "--memory",
        "4320",
        "--eif-path",
        "/home/ec2-user/app/server/signing_server.eif",
        "--enclave-cid",
        "16",
        "--enclave-name",
        enclave_name,
    ]
    if debug_mode:
        subprocess_args.append("--debug-mode")

    print("enclave args: {}".format(subprocess_args))

    proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE)  # nosec B603

    # returns b64 encoded plaintext
    nitro_cli_response = proc.communicate()[0].decode()

    return nitro_cli_response


def main():
    print("Starting signing server...")

    nitro_cli_run_call(enclave_name=ENCLAVE_NAME)

    while nitro_cli_describe_call(enclave_name=ENCLAVE_NAME):
        time.sleep(5)


if __name__ == "__main__":
    main()
