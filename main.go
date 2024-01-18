package main

import (
	"C"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs processtimeObjects
	if err := loadProcesstimeObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// link to the tracepoint prgram that we loaded into the kernel
	tp, err := link.Tracepoint("sched", "sched_switch", objs.CpuProcessingTime, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer tp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		var key processtimeKeyT

		// Iterate over all PIDs between 1 and 32767 (maximum PID on linux)
		// found in /proc/sys/kernel/pid_max
		for i := 1; i <= 32767; i++ {
			key.Pid = uint32(i)
			// Query the BPF map
			var mapValue processtimeValT
			if err := objs.ProcessTimeMap.Lookup(key, &mapValue); err == nil {
				log.Printf("CPU time for PID=%d: %dns\n", key.Pid, mapValue.ElapsedTime)
			}
		}
	}
}
