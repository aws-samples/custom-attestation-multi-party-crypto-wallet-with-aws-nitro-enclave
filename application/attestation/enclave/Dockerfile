#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

FROM python:3.12-slim-bullseye

ARG REGION_ARG
ENV REGION=$REGION_ARG

ARG DEPLOYMENT_ARG
ENV DEPLOYMENT=$DEPLOYMENT_ARG

WORKDIR /app
# additional binarys would be required for debugging
#RUN apt-get update && apt-get install git net-tools jq awscli iproute2 -y && apt-get clean

# additional dependencies for bash based credentials gathering
# RUN apt-get update && apt-get install curl jq iproute2 -y && apt-get clean

COPY ./enclave/requirements.txt ./
RUN pip3 install -r ./requirements.txt

# Copy all our files to the final image.
COPY ./third_party/nitriding-daemon/nitriding ./
COPY ./third_party/viproxy/proxy ./
COPY ./enclave/start.sh ./enclave/service.py ./
COPY ./enclave/src ./src

CMD ["./app/start.sh"]