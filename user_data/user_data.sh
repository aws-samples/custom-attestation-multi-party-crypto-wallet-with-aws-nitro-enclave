Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
bootcmd:
  - [ dnf, install, aws-nitro-enclaves-cli, aws-nitro-enclaves-cli-devel, htop, git, jq, -y ]
#packages:
#  - aws-nitro-enclaves-cli
#  - aws-nitro-enclaves-cli-devel
#  - htop
#  - git
#  - jq

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

set -x
set +e

# if specific operations should be executed in `dev` deployment use section below
#if [[ ${__DEV_MODE__} == "dev" ]]; then
#
#fi
#dnf update -y
# https://repost.aws/questions/QULw2LHDc0SXaVA-OW8gjjoA/issue-running-commands-on-amazon-linux-2023-t3-small-ec2-instance
# https://github.com/amazonlinux/amazon-linux-2023/issues/397
#dnf install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel git jq htop -y

usermod -aG docker ec2-user
usermod -aG ne ec2-user

ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
MEM_KEY=memory_mib
CPU_KEY=cpu_count
DEFAULT_MEM=6144
DEFAULT_CPU=2

sed -r "s/^(\s*$MEM_KEY\s*:\s*).*/\1$DEFAULT_MEM/" -i "$ALLOCATOR_YAML"
sed -r "s/^(\s*$CPU_KEY\s*:\s*).*/\1$DEFAULT_CPU/" -i "$ALLOCATOR_YAML"

VSOCK_PROXY_YAML=/etc/nitro_enclaves/vsock-proxy.yaml
cat <<'EOF' > $VSOCK_PROXY_YAML
allowlist:
- {address: kms.${__REGION__}.amazonaws.com, port: 443}
- {address: kms-fips${__REGION__}.amazonaws.com, port: 443}
- {address: 169.254.169.254, port: 80}

EOF

systemctl enable --now docker
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now nitro-enclaves-vsock-proxy.service

cd /home/ec2-user

if [[ ! -d ./app/server ]]; then
  mkdir -p ./app/server

  cd ./app/server
  cat <<'EOF' >>build_signing_server_enclave.sh
#!/usr/bin/bash

set -x
set -e

ACCOUNT_ID=$( aws sts get-caller-identity | jq -r '.Account' )
REGION=$(TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/placement/region)
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com
docker pull ${__OUTBOUND_PROXY_IMAGE_URI__}
docker pull ${__SIGNING_ENCLAVE_IMAGE_URI__}

nitro-cli build-enclave --docker-uri ${__SIGNING_ENCLAVE_IMAGE_URI__} --output-file signing_server.eif

EOF
  chmod +x build_signing_server_enclave.sh
  cd ../..
  chown -R ec2-user:ec2-user ./app

  sudo -H -u ec2-user bash -c "cd /home/ec2-user/app/server && ./build_signing_server_enclave.sh"
fi

# todo remove gates
if [[ ! -f /etc/systemd/system/nitro-signing-server.service ]]; then

  aws s3 cp ${__WATCHDOG_S3_URL__} /home/ec2-user/app/watchdog.py
  aws s3 cp ${__WATCHDOG_SYSTEMD_S3_URL__} /etc/systemd/system/enclave-watchdog.service
  aws s3 cp ${__IMDS_SYSTEMD_S3_URL__} /etc/systemd/system/enclave-imds-proxy.service

  chmod +x /home/ec2-user/app/watchdog.py

fi

# todo future dependencies for watchdog
pip3 install boto3
pip3 install botocore

# start and register the nitro signing server service for autostart
systemctl enable --now enclave-watchdog.service
systemctl enable --now enclave-imds-proxy.service

# docker over system process manager
docker run -d --restart unless-stopped --name gvproxy --privileged --security-opt seccomp=unconfined -p 443:443 -p 9090:9090 ${__OUTBOUND_PROXY_IMAGE_URI__}
--//--