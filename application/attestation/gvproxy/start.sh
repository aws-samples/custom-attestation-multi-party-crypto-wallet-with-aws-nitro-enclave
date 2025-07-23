#!/usr/bin/env sh
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set -e
set -x

VSOCK_SOCKET="/tmp/network.sock"

# function to setup port forwarding
setup_forward() {
  local_port=$1
  remote_port=$2
  curl --unix-socket /tmp/network.sock http:/unix/services/forwarder/expose \
    -X POST \
    -d "{\"local\":\":$local_port\",\"remote\":\"192.168.127.2:$remote_port\"}"
}

# in case that the container does experience a non gracefull shutdown, the tmp socket needs
# to be deleted before bringing gvisor up again to avoid an `address already in use` error:
# gvproxy exiting: cannot listen: listen unix /tmp/network.sock: bind: address already in use
if [ -S ${VSOCK_SOCKET} ]; then
  rm -f ${VSOCK_SOCKET}
fi

# start gvproxy in the background
./gvproxy -listen vsock://:1024 -listen unix:///tmp/network.sock &
GVPROXY_PID=$!

# wait for gvproxy to start
sleep 5

# Setup forward rules
setup_forward 443 443
setup_forward 9090 9090

# wait for the background process to finish
wait $GVPROXY_PID
