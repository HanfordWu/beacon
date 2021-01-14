#!/bin/bash

# save the docker image as a tarball and scp it to the device
docker save -o beacon-integration.tar beacon-integration:latest
scp beacon-integration.tar mel20-0100-0002-01sw:/home/crystalnet
rm beacon-integration.tar

# ssh to the device and load the docker image from the tarball
ssh mel20-0100-0002-01sw << EOF
  bash docker load -i beacon-integration.tar && rm beacon-integration.tar && docker system prune -f
EOF

