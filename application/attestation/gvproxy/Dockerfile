#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

FROM alpine:3.20
RUN apk update && apk upgrade
RUN apk --no-cache add curl
COPY ./third_party/gvisor-tap-vsock/bin/gvproxy-linux-amd64 ./gvproxy
COPY ./gvproxy/start.sh ./start.sh

CMD ["./start.sh"]
