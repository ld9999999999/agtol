all: approvald  approve  claude-sudo
	echo "..Done"

approvald: bindir
	go build -o bin/approvald ./cmd/approvald

approve: bindir
	go build -o bin/approve ./cmd/approve

claude-sudo: bindir
	go build -o bin/claude-sudo ./cmd/claude-sudo

bindir:
	mkdir -p bin
