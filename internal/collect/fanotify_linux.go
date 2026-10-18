//go:build linux

package collect

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// FIMWatcher is a fanotify-based real-time file-integrity watcher. It marks the
// server-pushed FIM watchlist and records paths modified since the last drain,
// giving the agent sub-poll-latency change detection on top of the periodic
// hashing scan (and catching transient modify-then-revert edits the poll would
// miss). Needs CAP_SYS_ADMIN (the agent runs as root); Start fails otherwise and
// the agent falls back to periodic FIM only.
//
// Marks are per-inode: a directory mark with FAN_EVENT_ON_CHILD catches writes
// to its direct children, but is not recursive — the periodic scan remains the
// authoritative, recursive backstop.
type FIMWatcher struct {
	fd     int
	mu     sync.Mutex
	marks  map[string]bool // paths currently marked
	hits   map[string]bool // paths modified since last Drain
	closed bool
}

// fanotify metadata header is 24 bytes: event_len(4) vers(1) reserved(1)
// metadata_len(2) mask(8) fd(4) pid(4). fd sits at offset 16.
const fanMetaLen = 24

const fanMark = unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_EVENT_ON_CHILD

// StartFIMWatch opens a fanotify group and begins reading events.
func StartFIMWatch() (*FIMWatcher, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	w := &FIMWatcher{fd: fd, marks: map[string]bool{}, hits: map[string]bool{}}
	go w.run()
	return w, nil
}

// SetPaths reconciles the kernel marks with the desired watchlist: adds marks
// for new paths, removes marks for dropped ones. Missing paths are skipped (they
// may appear later; a subsequent SetPaths re-marks them).
func (w *FIMWatcher) SetPaths(paths []string) {
	want := make(map[string]bool, len(paths))
	for _, p := range paths {
		want[p] = true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	for p := range w.marks {
		if !want[p] {
			unix.FanotifyMark(w.fd, unix.FAN_MARK_REMOVE, fanMark, unix.AT_FDCWD, p)
			delete(w.marks, p)
		}
	}
	for p := range want {
		if w.marks[p] {
			continue
		}
		if err := unix.FanotifyMark(w.fd, unix.FAN_MARK_ADD, fanMark, unix.AT_FDCWD, p); err == nil {
			w.marks[p] = true
		}
	}
}

func (w *FIMWatcher) run() {
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return // fd closed or unreadable: stop (best-effort sensor)
		}
		w.parse(buf[:n])
	}
}

// parse walks the fanotify records in b, resolves each delivered fd back to its
// path via /proc/self/fd, and records it. Each event carries an open fd that
// must be closed.
func (w *FIMWatcher) parse(b []byte) {
	for off := 0; off+fanMetaLen <= len(b); {
		evLen := int(binary.LittleEndian.Uint32(b[off:]))
		if evLen < fanMetaLen || off+evLen > len(b) {
			return
		}
		fd := int32(binary.LittleEndian.Uint32(b[off+16:]))
		off += evLen
		if fd < 0 {
			continue // FAN_NOFD / queue overflow
		}
		path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd)))
		unix.Close(int(fd))
		if err != nil {
			continue
		}
		w.mu.Lock()
		if !w.closed && len(w.hits) < 1024 {
			w.hits[path] = true
		}
		w.mu.Unlock()
	}
}

// Drain returns and clears the set of paths modified since the last call.
func (w *FIMWatcher) Drain() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.hits))
	for p := range w.hits {
		out = append(out, p)
	}
	w.hits = map[string]bool{}
	return out
}

func (w *FIMWatcher) Close() error {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	return unix.Close(w.fd) // unblocks the read loop
}
