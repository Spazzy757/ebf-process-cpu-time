// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type processtimeKeyT struct{ Pid uint32 }

type processtimeValT struct {
	StartTime   uint64
	ElapsedTime uint64
}

// loadProcesstime returns the embedded CollectionSpec for processtime.
func loadProcesstime() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ProcesstimeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load processtime: %w", err)
	}

	return spec, err
}

// loadProcesstimeObjects loads processtime and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*processtimeObjects
//	*processtimePrograms
//	*processtimeMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadProcesstimeObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadProcesstime()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// processtimeSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type processtimeSpecs struct {
	processtimeProgramSpecs
	processtimeMapSpecs
}

// processtimeSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type processtimeProgramSpecs struct {
	CpuProcessingTime *ebpf.ProgramSpec `ebpf:"cpu_processing_time"`
}

// processtimeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type processtimeMapSpecs struct {
	ProcessTimeMap *ebpf.MapSpec `ebpf:"process_time_map"`
}

// processtimeObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadProcesstimeObjects or ebpf.CollectionSpec.LoadAndAssign.
type processtimeObjects struct {
	processtimePrograms
	processtimeMaps
}

func (o *processtimeObjects) Close() error {
	return _ProcesstimeClose(
		&o.processtimePrograms,
		&o.processtimeMaps,
	)
}

// processtimeMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadProcesstimeObjects or ebpf.CollectionSpec.LoadAndAssign.
type processtimeMaps struct {
	ProcessTimeMap *ebpf.Map `ebpf:"process_time_map"`
}

func (m *processtimeMaps) Close() error {
	return _ProcesstimeClose(
		m.ProcessTimeMap,
	)
}

// processtimePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadProcesstimeObjects or ebpf.CollectionSpec.LoadAndAssign.
type processtimePrograms struct {
	CpuProcessingTime *ebpf.Program `ebpf:"cpu_processing_time"`
}

func (p *processtimePrograms) Close() error {
	return _ProcesstimeClose(
		p.CpuProcessingTime,
	)
}

func _ProcesstimeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed processtime_bpfel.o
var _ProcesstimeBytes []byte
