#!/bin/bash

HOST_DEVICE=$1
if [ -z "$1" ]; then
  HOST_DEVICE="BL20-0100-0100-02SW"
fi					

scp -r "crystalnet@$HOST_DEVICE:/home/crystalnet/moby-bench-results" .

ssh "crystalnet@$HOST_DEVICE" << EOF
  bash rm -r /home/crystalnet/moby-bench-results
EOF

cd moby-bench-results
go tool pprof -svg cpuprof.out
go tool pprof -svg memprof.out
