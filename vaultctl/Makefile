.PHONY: build build-linux build-windows test clean

# Default: build for the current platform
build:
	go build -o vaultctl .

# Cross-compile for Linux (amd64)
build-linux:
	GOOS=linux GOARCH=amd64 go build -o dist/vaultctl-linux-amd64 .

# Cross-compile for Windows (amd64)
build-windows:
	GOOS=windows GOARCH=amd64 go build -o dist/vaultctl-windows-amd64.exe .

# Build for both platforms
build-all: build-linux build-windows

test:
	go test -v ./...

clean:
	rm -rf dist/ vaultctl vaultctl.exe
