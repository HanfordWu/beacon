#!/bin/bash

HOST_DEVICE=$1
if [ -z "$1" ]; then
	HOST_DEVICE="BL20-0100-0100-02SW"
fi

# make the benchmark results directory beforehand so it's not owned by root
ssh crystalnet@$HOST_DEVICE << EOF
  mkdir /home/crystalnet/moby-bench-results
EOF

DOCKER_HOST="tcp://$HOST_DEVICE:50050" docker run --rm --network host -v /home/crystalnet/moby-bench-results:/moby-bench-results beacon-integration:latest
