build-static:
	go build -ldflags="-extldflags=-static"

build-ipv6:
	docker build --no-cache -t test-ipv6:latest .

save-ipv6:
	docker save -o test-ipv6.tar test-ipv6:latest

load-ipv6:
	docker load -i test-ipv6.tar

run-ipv6:
	docker run \
		--rm \
		--name test-ipv6 \
		--memory 2g \
		--network host \
		--log-opt max-size=5m \
		-e "src_device=lo" \
		-e "dst_device=lo" \
		-e "src_ip=::1" \
		-e "dst_ip=::1" \
		-e "src_mac=00:00:00:00:00:00" \
		-e "dst_mac=00:00:00:00:00:00" \
		-v /var/run/command-api.sock:/var/run/command-api.sock \
		test-ipv6:latest

run-static:
	sudo ./test_ipv6 lo lo ::1 ::1 ::1,::1,::1
