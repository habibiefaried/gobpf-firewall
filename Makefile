all:
	go mod tidy
	go build -o firewall
test:
	go mod tidy
	go test -v