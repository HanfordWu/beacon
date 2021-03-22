#!/bin/bash

HOST_DEVICE=$1
if [ -z "$1" ]
then
  HOST_DEVICE="BL20-0100-0100-02SW"
fi

echo $HOST_DEVICE

# save the docker image as a tarball and scp it to the device
docker save -o beacon-integration.tar beacon-integration:latest
scp beacon-integration.tar "crystalnet@$HOST_DEVICE:/home/crystalnet"
rm beacon-integration.tar

# ssh to the device and load the docker image from the tarball
ssh "crystalnet@$HOST_DEVICE" << EOF
  bash docker load -i beacon-integration.tar && rm beacon-integration.tar && docker system prune -f
EOF

