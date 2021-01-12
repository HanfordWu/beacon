build:
	go build ./...

test:
	go test

integration-test:
	docker build . -f ./dockerfiles/Dockerfile.integration -t beacon-integration:latest  && ./bin/upload_integration_image.sh && ./bin/run_integration_container.sh
