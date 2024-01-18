.PHONY: run
run:
	@go generate
	@CGO_ENABLED="1" \
		CGO_CFLAGS="-I /usr/include/bpf" \
		go build -o processtime
	@sudo ./processtime
