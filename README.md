# EBF Process CPU Time

This is a simplistic example of how to get the processing tim of certain
processes.  


## Regenerating the Go bindings


we use the very handy tool [bpf2go](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) to generate our Golang structs. If you make changes to the [processtime.c](./processtime.c) file you will need to rerun this
```bash
go generate
```

