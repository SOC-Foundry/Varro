//go:build ignore

// Kernel sensors, CO-RE-free so one compiled object runs across kernels
// (>=5.8 for ring buffers):
//   1. exec: every process exec -> {pid, comm}.
//   2. connect: every outbound TCP connect (CLOSE -> SYN_SENT, which fires in
//      the connecting task's context) -> {pid, comm, dest, port}. Catches
//      short-lived connections the periodic /proc scan misses, with in-kernel
//      process attribution that conntrack lacks.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

struct event {
	__u32 pid;
	__u8  comm[16];
};

// Emit the type into BTF so bpf2go generates a matching Go struct.
struct event *_unused_event __attribute__((unused));

// Matches the sock/inet_sock_set_state tracepoint format (ABI-stable layout,
// so no CO-RE is needed to read it).
struct inet_state_args {
	__u64 _pad;         // common header (type/flags/preempt/pid)
	__u64 skaddr;       // offset 8
	int   oldstate;     // 16
	int   newstate;     // 20
	__u16 sport;        // 24
	__u16 dport;        // 26 (already host-order in this tracepoint)
	__u16 family;       // 28 (AF_INET=2, AF_INET6=10)
	__u16 protocol;     // 30 (IPPROTO_TCP=6)
	__u8  saddr[4];     // 32
	__u8  daddr[4];     // 36
	__u8  saddr_v6[16]; // 40
	__u8  daddr_v6[16]; // 56
};

struct conn_event {
	__u32 pid;
	__u16 dport;
	__u16 family;
	__u8  daddr[4];
	__u8  daddr6[16];
	__u8  comm[16];
};
struct conn_event *_unused_conn __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} conns SEC(".maps");

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

SEC("tracepoint/sock/inet_sock_set_state")
int trace_connect(struct inet_state_args *ctx) {
	if (ctx->protocol != 6) // IPPROTO_TCP
		return 0;
	if (ctx->oldstate != 7 || ctx->newstate != 2) // TCP_CLOSE -> TCP_SYN_SENT
		return 0;
	struct conn_event *e = bpf_ringbuf_reserve(&conns, sizeof(struct conn_event), 0);
	if (!e)
		return 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->dport = ctx->dport;
	e->family = ctx->family;
	__builtin_memcpy(e->daddr, ctx->daddr, 4);
	__builtin_memcpy(e->daddr6, ctx->daddr_v6, 16);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
