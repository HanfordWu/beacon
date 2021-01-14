#!/bin/bash

scp -r crystalnet@mel20-0100-0002-01sw:/home/crystalnet/moby-bench-results .

ssh mel20-0100-0002-01sw << EOF
  bash rm -r /home/crystalnet/moby-bench-results
EOF

cd moby-bench-results
go tool pprof -svg cpuprof.out
go tool pprof -svg memprof.out
