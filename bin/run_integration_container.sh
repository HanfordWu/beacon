#!/bin/bash

# make the benchmark results directory beforehand so it's not owned by root
ssh mel20-0100-0002-01sw << EOF
  mkdir /home/crystalnet/moby-bench-results
EOF

DOCKER_HOST="tcp://mel20-0100-0002-01sw:50050" docker run --rm --network host -v /home/crystalnet/moby-bench-results:/moby-bench-results beacon-integration:latest
