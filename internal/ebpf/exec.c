//go:build ignore

// Minimal exec tracer: fires on every process exec and pushes {pid, comm} to
// a ring buffer. Deliberately avoids CO-RE / vmlinux.h and kernel-struct
// access so one compiled object runs across kernels (≥5.8 for ring buffer).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

struct event {
	__u32 pid;
	__u8  comm[16];
};

// Emit the type into BTF so bpf2go generates a matching Go struct.
struct event *_unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(void *ctx) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e)
		return 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
