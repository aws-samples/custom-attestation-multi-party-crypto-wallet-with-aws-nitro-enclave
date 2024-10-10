#!/usr/bin/env bash

set -eo pipefail
set +x

# set default behaviour
build_dependencies="true"
bootstrap_cdk="true"
deploy_cdk="true"
create_key_policy="true"
run_attestation_test_public="true"
run_sss_test_public="true"
# just available if stack has been created with `test` prefix due to the required lambda resource
run_attestation_test_lambda="false"
run_sss_test_lambda="false"
run_cli_test="true"
# if set to "true" cdk destroy will be called any time an error occurs
destroy_cdk_on_error="false"
destroy_cdk_on_exit="true"

# override external otherwise serverless proxy does not become available
export CDK_PREFIX="e2e"
export CDK_DEPLOY_ACCOUNT=$(aws sts get-caller-identity | jq -r '.Account')
# if run in a workshop account in region different from us-east-1, region needs to be allow listed
export CDK_DEPLOY_REGION=us-east-1
export C9_PUBLIC_IP="$(curl https://checkip.amazonaws.com)"

# target outfile for cdk out params
outfile="${1:-$CDK_PREFIX_e2e_test_outfile.json}"

CREATE_KEY_REQUEST='{"recovery_public_key_b64":""}'
CREATE_SIGNATURE_REQUEST='{"key_shard_b64":"","pub_key":"","tx_hash":""}'

LAMBDA_REQUEST='{"operation":"","transaction_payload":{"url":"","payload":""}}'
ATTESTATION_URL="/enclave/attestation?nonce=ffffffffffffffffffffffffffffffffffffffff"
SSS_KEY_URL="/app/sss/key"
SSS_SIGNATURE_URL="/app/sss/signature"

ENCLAVE_APP_FOLDER="./application/attestation/enclave"
SHAMIR_CLI_PATH="${ENCLAVE_APP_FOLDER}/shamir_cli.py"
SHAMIR_CLI_DEPENDENCIES_PATH="${ENCLAVE_APP_FOLDER}/requirements.txt"

THIRD_PARTY_FOLDER="./application/attestation/third_party"
PROXY_BINARY_PATH="${THIRD_PARTY_FOLDER}/viproxy/proxy"

assert() {
  E_PARAM_ERR=98
  E_ASSERT_FAILED=99

  if [ -z "$2" ]; then
    return $E_PARAM_ERR
  fi

  message=$1
  assertion=$2

  if [ ! "${assertion}" ]; then
    echo "❌ $message"
    exit $E_ASSERT_FAILED
  else
    echo "✅ $message"
    return
  fi
}

cleanup() {
  rm -f *cli.tmp recipient_private_key.pem recipient_public_key.pem
  cdk destroy ${CDK_PREFIX}NitroWalletSSS --force
}

if [[ ${destroy_cdk_on_error} = "true" ]]; then
  trap cleanup ERR
fi

lambda_request() {
  local lambda_function_name=$1
  local method=$2
  local url=$3
  local payload=$4
  local outvar=$5

  printf "\n**** lambda %s request ****\n" "${method}"

  local lambda_request_payload
  if [[ -n ${payload} ]]; then
    lambda_request_payload=$(jq --argjson inject "${payload}" '.transaction_payload.payload = $inject' <<<"${LAMBDA_REQUEST}")
  else
    lambda_request_payload="${LAMBDA_REQUEST}"
  fi

  echo "${lambda_request_payload}" | jq '.operation="'${method}'" | .transaction_payload.url="'${url}'"' >.tmp.invoke.payload
  cat .tmp.invoke.payload

  aws lambda invoke \
    --region "${CDK_DEPLOY_REGION}" \
    --cli-binary-format raw-in-base64-out \
    --function-name "${lambda_function_name}" \
    --payload file://.tmp.invoke.payload .tmp.invoke.out

  # set reference to variable external to current function scope so that
  declare -n ref=${outvar}
  # shellcheck disable=SC2034
  ref=$(cat .tmp.invoke.out)
  cat .tmp.invoke.out
  rm .tmp.invoke.*
}

if [ -z "${outfile}" ]; then
  echo "usage: $0 <outfile>"
  exit 1
fi

# install and build external dependencies
if [[ ${build_dependencies} = "true" ]]; then
  # viproxy
  ./scripts/build_vsock_proxy.sh

  cd "${THIRD_PARTY_FOLDER}"

  # nitriding daemon (linux, amd64)
  if [[ ! -d nitriding-daemon ]]; then
    # todo bug v1.4.2 has different interface / bug
    # --depth 1 --branch v1.4.2
    git clone https://github.com/brave/nitriding-daemon.git
  fi
  cd nitriding-daemon
  make nitriding
  cd ..

  # nitride (needs to be compiled for local os/architecture)
  # todo no version tag yet
  if [[ ! -d nitrite ]]; then
    git clone https://github.com/hf/nitrite.git
  fi
  cd nitrite
  go build -o nitrite ./cmd/nitrite
  cd ..

  # gvisor (linux, amd64)
  if [[ ! -d gvisor-tap-vsock ]]; then
    git clone --depth 1 --branch v0.7.4 https://github.com/containers/gvisor-tap-vsock.git
  fi
  cd gvisor-tap-vsock
  CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -ldflags '-extldflags "-static"' -o bin/gvproxy-linux-amd64 ./cmd/gvproxy
  cd ../../../..

fi

pip3 show aws-cdk-lib 1>/dev/null
if [[ $? -ne 0 ]]; then
  pip3 install -r requirements.txt
fi

# bootstrap cdk
if [[ ${bootstrap_cdk} = "true" ]]; then
  cdk bootstrap aws://${CDK_DEPLOY_ACCOUNT}/${CDK_DEPLOY_REGION}
fi

if [[ ${deploy_cdk} = "true" ]]; then
  # deploy cdk stack
  # todo subsequent calls will fail due to nlb issue -> takes time to propagate new ec2 instance
  cdk deploy ${CDK_PREFIX}NitroWalletSSS -O ${outfile} --require-approval never

  echo "waiting for stack to settle"
  sleep 45
fi

# parse outfile and extract all values required by the subsequent tests
lambda_function_name=$(jq -r '.'"${CDK_PREFIX}"'NitroWalletSSS.LambdaFunctionName' "${outfile}")
kms_key_id=$(jq -r '.'"${CDK_PREFIX}"'NitroWalletSSS.KMSKeyID' "${outfile}")
target_group_arn=$(jq -r '.'"${CDK_PREFIX}"'NitroWalletSSS.NitroLoadBalancerTargetGroupArn' "${outfile}")
endpoint=$(jq -r '.'"${CDK_PREFIX}"'NitroWalletSSS.NLBDNSAddress' "${outfile}")

# before continuing validate that target group health is `healthy` again
echo -n "waiting for target group to become healthy "
while true; do
  tg_health=$(aws elbv2 describe-target-health \
    --region "${CDK_DEPLOY_REGION}" \
    --target-group-arn "${target_group_arn}" | jq -r '.TargetHealthDescriptions[0].TargetHealth.State')
  if [[ "${tg_health}" == "healthy" ]]; then
    break
  else
    echo -n "."
    sleep 5
  fi
done

echo -en "\nwaiting for https endpoint to become responsive "
while true; do
  # send get request with 5 sec timeout and wait till https endpoint becomes responsive
  r=$(curl -k -s -m 5 "https://${endpoint}:443" || true)
  if [[ $r = "GET request for /" ]]; then
    echo ""
    break
  fi
  echo -n "."
done

# default curl timeout is 5min
if [[ ${run_attestation_test_public} = "true" ]]; then
  attestation_doc=$(curl -k -s "https://${endpoint}${ATTESTATION_URL}")
  attestation_doc_parsed=$(echo "${attestation_doc}" | xargs ${THIRD_PARTY_FOLDER}/nitrite/nitrite -attestation)
  echo "${attestation_doc_parsed}" | jq '.'
fi

if [[ ${run_attestation_test_lambda} = "true" ]]; then
  lambda_request "${lambda_function_name}" "GET" ${ATTESTATION_URL} "" "attestation_doc"
  echo "${attestation_doc}"

  attestation_doc_parsed=$(echo "${attestation_doc}" | xargs ${THIRD_PARTY_FOLDER}/nitrite/nitrite -attestation)
  echo "${attestation_doc_parsed}" | jq '.'
fi

if [[ ${create_key_policy} = "true" ]]; then
  ./scripts/generate_key_policy.sh ${outfile} >.tmp.key_policy.out
  aws kms put-key-policy \
    --region "${CDK_DEPLOY_REGION}" \
    --policy-name default \
    --key-id "${kms_key_id}" \
    --policy file://.tmp.key_policy.out
  rm .tmp.key_policy.out
fi

# generate recovery private/public key pair
openssl ecparam -name secp384r1 -genkey -noout -out recipient_private_key.pem
openssl ec -in recipient_private_key.pem -pubout -out recipient_public_key.pem
# -w 0 not supported on macos
recovery_public_key_b64=$(cat recipient_public_key.pem | base64 | tr -d \\n)

if [[ ${run_sss_test_public} = "true" ]]; then

  create_key_request=$(echo "${CREATE_KEY_REQUEST}" | jq -c '.recovery_public_key_b64="'${recovery_public_key_b64}'"')
  #  lambda_request "${lambda_function_name}" "POST" ${SSS_KEY_URL} ${create_key_request} "key_shard"
  key_shard=$(curl -k -s --header "Content-Type: application/json" \
    --request POST \
    --data '{"recovery_public_key_b64":"'"$recovery_public_key_b64"'"}' \
    "https://${endpoint}${SSS_KEY_URL}")

  jq '.' <<<"${key_shard}"

  key_shard_b64=$(echo "${key_shard}" | jq -r '.key_shard')
  pub_key=$(echo "${key_shard}" | jq -r '.public_key')
  tx_hash="42deadbeef1337"

  #  # todo assert 403 (just first iteration)
  #  sign_tx_request=$(echo "${CREATE_SIGNATURE_REQUEST}" | jq -c '.key_shard_b64="'${key_shard_b64}'" | .pub_key="'${pub_key}'" | .tx_hash="'${tx_hash}'"')
  #  lambda_request "${lambda_function_name}" "POST" ${SSS_SIGNATURE_URL} ${sign_tx_request} "tx_signature"
  #  echo "${tx_signature}"

  #  sign_tx_request=$(echo "${CREATE_SIGNATURE_REQUEST}" | jq -c '.key_shard_b64="'${key_shard_b64}'" | .pub_key="'${pub_key}'" | .tx_hash="'${tx_hash}'"')
  tx_signature=$(
    curl -k -s --header "Content-Type: application/json" \
      --request POST \
      --data '{"key_shard_b64":"'"${key_shard_b64}"'","pub_key":"'"${pub_key}"'","tx_hash":"'"${tx_hash}"'"}' \
      "https://${endpoint}${SSS_SIGNATURE_URL}"
  )
  jq '.' <<<"${tx_signature}"

fi

if [[ ${run_sss_test_lambda} = "true" ]]; then

  create_key_request=$(echo "${CREATE_KEY_REQUEST}" | jq -c '.recovery_public_key_b64="'${recovery_public_key_b64}'"')
  lambda_request "${lambda_function_name}" "POST" ${SSS_KEY_URL} ${create_key_request} "key_shard"
  echo "${key_shard}"

  key_shard_b64=$(echo "${key_shard}" | jq -r '.key_shard')
  pub_key=$(echo "${key_shard}" | jq -r '.public_key')
  tx_hash="42deadbeef1337"

  #  # todo assert 403 (just first iteration)
  #  sign_tx_request=$(echo "${CREATE_SIGNATURE_REQUEST}" | jq -c '.key_shard_b64="'${key_shard_b64}'" | .pub_key="'${pub_key}'" | .tx_hash="'${tx_hash}'"')
  #  lambda_request "${lambda_function_name}" "POST" ${SSS_SIGNATURE_URL} ${sign_tx_request} "tx_signature"
  #  echo "${tx_signature}"

  sign_tx_request=$(echo "${CREATE_SIGNATURE_REQUEST}" | jq -c '.key_shard_b64="'${key_shard_b64}'" | .pub_key="'${pub_key}'" | .tx_hash="'${tx_hash}'"')
  lambda_request "${lambda_function_name}" "POST" ${SSS_SIGNATURE_URL} ${sign_tx_request} "tx_signature"
  jq '.' <<<"${tx_signature}"

fi

if [[ ${run_cli_test} = "true" ]]; then

  pip3 install -r ${SHAMIR_CLI_DEPENDENCIES_PATH}

  echo "${key_shard}" | jq -r '.recovery.shard' >recovery_shard_cli.tmp
  echo "${key_shard}" | jq -r '.recovery.ephemeral_public_key' >ephemeral_public_key_pem_cli.tmp

  decrypted_key_shard_out=$(${SHAMIR_CLI_PATH} decrypt recovery_shard_cli.tmp recipient_private_key.pem ephemeral_public_key_pem_cli.tmp)
  jq '.' <<<"${decrypted_key_shard_out}"
  #  assert "decrypted message needs to be 45 base64 encoded bytes long" "$(jq -r '.decrypted_message' | wc -c) == 45"

  combine_out=$(${SHAMIR_CLI_PATH} combine "${key_shard_b64}" "$(jq '.decrypted_message' <<<"${decrypted_key_shard_out}")" "${tx_hash}")
  jq '.' <<<"${combine_out}"
  signature_b64_cli=$(jq -r '.signature_b64' <<<"${combine_out}")
  hash_value_64_cli=$(jq -r '.hash_value_b64' <<<"${combine_out}")

  assert "reassembled public key needs to be equal to enclave public key" "$(jq -r '.public_key' <<<"${combine_out}") == ${pub_key}"

  # generate pcr sha384 value and compare it with the one in the attestation doc
  proxy_binary_pcr_out=$(${SHAMIR_CLI_PATH} pcr ${PROXY_BINARY_PATH})
  jq '.' <<<"${proxy_binary_pcr_out}"

  if [[ -n "${attestation_doc_parsed}" ]]; then
    pcr_16=$(jq -r '.pcrs."16"' <<<"${attestation_doc_parsed}" | base64 -d | xxd -p -c 0)
    assert "proxy binary pcr value needs to be equal to enclave pcr value" "$(jq -r '.pcr_value' <<<"${proxy_binary_pcr_out}") == "${pcr_16}""
  else
    echo "attestation doc needs to be set to run this test - turn on run_attestation_test boolean flag and run again"
  fi

  echo "decompress x962 public key to DER"
  jq -r '.public_key' <<<"${combine_out}" >./public_key_x962_cli.tmp
  decompressed_public_key_der=$(${SHAMIR_CLI_PATH} decompress ./public_key_x962_cli.tmp)
  jq '.' <<<"${decompressed_public_key_der}"

  decompressed_key_der_b64=$(jq -r '.decompressed_pub_key_der_b64' <<<"${decompressed_public_key_der}")

  cli_signature_valid=$(${SHAMIR_CLI_PATH} verify "${signature_b64_cli}" "${decompressed_key_der_b64}" "${hash_value_64_cli}")
  assert "cli signature needs to be valid" "$(jq -r '.is_valid' <<<"${cli_signature_valid}") == "true""

  #  ensure that the enclave signature is not null
  if [[ -n "${tx_signature}" ]]; then
    # xxd -r -p | base64
    signature_b64_enclave=$(jq -r '.signature' <<<"${tx_signature}")
    enclave_signature_valid=$(${SHAMIR_CLI_PATH} verify "${signature_b64_enclave}" "${decompressed_key_der_b64}" "${hash_value_64_cli}")
    assert "enclave signature needs to be valid" "$(jq -r '.is_valid' <<<"${enclave_signature_valid}") == "true""
  else
    echo "tx_signature needs to be set to run this test - turn on run_sss_test boolean flag and run again"
  fi
fi

if [[ ${destroy_cdk_on_exit} = "true" ]]; then
  cleanup
fi
