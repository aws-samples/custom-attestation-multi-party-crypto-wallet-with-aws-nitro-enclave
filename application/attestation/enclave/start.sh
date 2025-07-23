#!/usr/bin/env sh
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

IMDS_ENDPOINT=127.0.0.1
#ip addr add 169.254.169.254/16 dev lo
#IN_ADDRS=169.254.169.254:80 OUT_ADDRS=3:8002 ./app/proxy &

# connect to imds proxy on parent instance
IN_ADDRS=${IMDS_ENDPOINT}:80 OUT_ADDRS=3:8002 ./app/proxy &

# https://github.com/brave/nitriding-daemon/blob/master/util.go#L68
#  -debug \
#  -fqdn-leader leader.example.com \
./app/nitriding -fqdn example.com \
  -ext-pub-port 443 \
  -prometheus-namespace enclave \
  -prometheus-port 9090 \
  -intport 8080 \
  -appwebsrv http://127.0.0.1:8088 \
  -wait-for-app &
echo "[sh] Started nitriding."
sleep 1

./app/service.py &
SSS_APP_PID=$!
echo "[sh] Started sss service"

# if sss app crashes, kill nitriding too
wait $SSS_APP_PID

# keep main thread alive - imds credentials can be gathered using the commented shell commands below too

# while true; do
#    token=$(curl -X PUT "http://${IMDS_ENDPOINT}/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
#    role_name=$(curl -H "X-aws-ec2-metadata-token: ${token}" http://${IMDS_ENDPOINT}/latest/meta-data/iam/security-credentials/)
#    creds=$(curl -H "X-aws-ec2-metadata-token: ${token}" http://${IMDS_ENDPOINT}/latest/meta-data/iam/security-credentials/${role_name})
#    echo ${creds} | jq '.'
#    echo "[sh] Got temporary token"
#  sleep 30
# done
