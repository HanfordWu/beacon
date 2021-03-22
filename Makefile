HOST_DEVICE ?= BL20-0100-0100-02SW

build:
	go build ./...

test:
	go test

integration-test:
	docker build . -f ./dockerfiles/Dockerfile.integration -t beacon-integration:latest && \
		./bin/upload_integration_image.sh $(HOST_DEVICE) && \
		./bin/run_integration_container.sh $(HOST_DEVICE) && \
		./bin/retrieve_pprof_results.sh $(HOST_DEVICE)
