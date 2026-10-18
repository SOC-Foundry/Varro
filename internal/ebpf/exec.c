//go:build ignore

// Kernel sensors, CO-RE-free so one compiled object runs across kernels
// (>=5.8 for ring buffers):
//   1. exec: every process exec -> {pid, comm}.
//   2. connect: every outbound TCP connect (CLOSE -> SYN_SENT, which fires in
//      the connecting task's context) -> {pid, comm, dest, port}. Catches
//      short-lived connections the periodic /proc scan misses, with in-kernel
//      process attribution that conntrack lacks.
//   3. file-write: every openat() for write under a high-signal persistence root
//      (/etc, /boot, /root) -> {pid, comm, path}. The path root is gated in the
//      kernel so the ring buffer stays quiet (the firehose of /tmp, /var, /home
//      and relative opens never reaches user space); the agent refines further.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// openat() write-intent flags (octal, as in <fcntl.h> — not pulled in here).
#define O_WRONLY 00000001
#define O_RDWR   00000002
#define O_CREAT  00000100
#define O_TRUNC  00001000

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

// Matches the syscalls/sys_enter_openat tracepoint format. Syscall args are
// stored as unsigned long starting at offset 16 (ABI-stable, so no CO-RE).
struct openat_args {
	__u64 _common;      // common header (type/flags/preempt/pid)
	__s32 __syscall_nr; // 8
	__u32 _pad;         // 12 (args are 8-aligned)
	__u64 dfd;          // 16
	__u64 filename_ptr; // 24  const char __user *
	__u64 flags;        // 32
	__u64 mode;         // 40
};

struct file_event {
	__u32 pid;
	__u8  comm[16];
	__u8  filename[256];
};
struct file_event *_unused_file __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} files SEC(".maps");

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

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct openat_args *ctx) {
	if (!(ctx->flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
		return 0; // read-only open, ignore
	const char *fn = (const char *)ctx->filename_ptr;
	// Gate on the path root in-kernel so the ring buffer only ever carries
	// opens under high-signal persistence roots, not the write firehose.
	char pfx[6] = {};
	if (bpf_probe_read_user(&pfx, sizeof(pfx), fn) != 0)
		return 0;
	if (pfx[0] != '/')
		return 0; // relative path (cwd-dependent), skip
	char a = pfx[1], b = pfx[2], c = pfx[3], d = pfx[4];
	int ok = (a == 'e' && b == 't' && c == 'c' && d == '/')  // /etc/
	      || (a == 'b' && b == 'o' && c == 'o' && d == 't')  // /boot
	      || (a == 'r' && b == 'o' && c == 'o' && d == 't'); // /root
	if (!ok)
		return 0;
	struct file_event *e = bpf_ringbuf_reserve(&files, sizeof(struct file_event), 0);
	if (!e)
		return 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fn);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_connect(struct inet_state_args *ctx) {
	if (ctx->protocol != 6) // IPPROTO_TCP
		return 0;
	if (ctx->oldstate != 7 || ctx->newstate != 2) // TCP_CLOSE -> TCP_SYN_SENT
		return 0;
	if (ctx->family == 2 && ctx->daddr[0] == 127) // skip IPv4 loopback (127.0.0.0/8)
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
