#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set -e
set +x

output=${1}

# instance id
asg_name=$(jq -r '.'${CDK_PREFIX}'NitroWalletSSS.ASGGroupName' "${output}")
instance_id=$(./scripts/get_asg_instances.sh "${asg_name}" | head -n 1)

# pcr_0
# pcr_0 for debug mode: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
pcr_0=$(./scripts/get_pcr0.sh "${instance_id}")

# ec2 role
ec2_role_arn=$(jq -r '.'${CDK_PREFIX}'NitroWalletSSS.EC2InstanceRoleARN' "${output}")

# lambda role
lambda_execution_arn=$(jq -r '.'${CDK_PREFIX}'NitroWalletSSS.LambdaExecutionRoleARN' "${output}")

# account
account_id=$(aws sts get-caller-identity | jq -r '.Account')

# Use the jq --arg option to pass shell variables into jq
jq --arg pcr_0 "$pcr_0" \
   --arg ec2_role_arn "$ec2_role_arn" \
   --arg lambda_execution_arn "$lambda_execution_arn" \
   --arg account_id "arn:aws:iam::${account_id}:root" \
   '.Statement[0].Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:PCR0"=$pcr_0 |
    .Statement[0].Principal.AWS=$ec2_role_arn |
    .Statement[1].Principal.AWS=$ec2_role_arn |
    .Statement[2].Principal.AWS=$account_id' \
   ./scripts/kms_key_policy_template.json
