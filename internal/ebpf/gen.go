// Package ebpf provides the kernel exec-event sensor (Linux only).
package ebpf

// Regenerate the embedded BPF object + Go bindings after editing exec.c:
//   go generate ./internal/ebpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel exec exec.c
