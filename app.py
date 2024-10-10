#!/usr/bin/env python3

#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import os
from aws_cdk import App, Environment, Aspects

from nitro_wallet.nitro_wallet_stack import NitroWalletStack
import cdk_nag

app = App()

prefix = os.getenv("CDK_PREFIX", "dev")
region = os.environ.get("CDK_DEPLOY_REGION")
account = os.environ.get("CDK_DEPLOY_ACCOUNT")

if region is None or account is None:
    raise ValueError(
        "CDK_DEPLOY_REGION and CDK_DEPLOY_ACCOUNT must be set in the environment"
    )

NitroWalletStack(
    app,
    f"{prefix}NitroWalletSSS",
    params={"deployment": prefix, "application_type": "attestation"},
    env=Environment(region=region, account=account),
)

Aspects.of(app).add(cdk_nag.AwsSolutionsChecks())
app.synth()
