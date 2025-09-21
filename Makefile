.PHONY: build-frontend

build-frontend:
	@echo "Building frontend Docker image with REACT_APP_* build args from environment"
	./build-frontend.sh
