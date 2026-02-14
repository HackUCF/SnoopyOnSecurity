.PHONY: install build-proto clean test

install:
	pip install -r requirements.txt
	pip install -e .

build-proto:
	# Generate Python protobuf classes
	# Note: Requires protoc to be installed
	python3 -m grpc_tools.protoc \
		--python_out=. \
		--grpc_python_out=. \
		--proto_path=proto \
		--proto_path=/usr/local/include \
		proto/c2.proto proto/eldritch.proto proto/dns.proto proto/portal.proto || \
		echo "Warning: protoc not found. Install with: apt-get install protobuf-compiler"

build-keyhook:
	cd keyhook && make

clean:
	find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -rf build/ dist/ *.egg-info/
	# Note: *_pb2.py files are kept (required for runtime)

test:
	python3 -m pytest tests/ -v
