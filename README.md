Make sure you have the filter.c file containing the eBPF code in the same directory as in Go program. 
This Go program loads the eBPF program from the filter.c file, attaches it to a socket filter, and configures the port number using a BPF map.
