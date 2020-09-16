docker run --rm \
    -v $GOPATH/src/github.com/trstruth/beacon:/beacon \
    -v $HOME/.ssh:/root/.ssh \
    arista-gopacket-compiler:braceroute && \
scp braceroute netscript1_rw@stg30-0100-0001-02sw:/home/netscript1_rw/
