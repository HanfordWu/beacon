FROM golang:1.15

WORKDIR /go/src/app

RUN apt-get update && apt-get install libpcap0.8 && apt-get install -y libpcap-dev
RUN ln -s /usr/lib/libpcap.so.1.9.1 /usr/lib/libpcap.so.0.8

COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

CMD ["app"]
