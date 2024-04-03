package projectaccuknox

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

func main() {
	// Create a new BPF module
	module := ebpf.NewModuleFromFile("filter.c")
	if module == nil {
		fmt.Fprintf(os.Stderr, "Failed to load BPF module\n")
		os.Exit(1)
	}
	defer module.Close()

	// Find the BPF program function in the module
	fn, err := module.Load("drop_tcp_port", ebpf.BPF_PROG_TYPE_SOCKET_FILTER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load BPF program: %v\n", err)
		os.Exit(1)
	}

	// Attach the BPF program to a socket filter
	filter := ebpf.SocketFilter{
		Program: fn,
	}
	err = filter.Attach(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach BPF program: %v\n", err)
		os.Exit(1)
	}
	defer filter.Close()

	// Get the map to configure the port number
	portMap := module.Map("port_map")
	if portMap == nil {
		fmt.Fprintf(os.Stderr, "Failed to find port_map\n")
		os.Exit(1)
	}

	// Set the configurable port number
	port := 4040
	err = portMap.Put(uint32(0), uint32(port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set port number: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("eBPF program attached. Dropping TCP packets on port %d\n", port)
	fmt.Println("Press Ctrl+C to stop")

	
}
