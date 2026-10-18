//go:build !linux

package collect

import "errors"

// FIMWatcher is a no-op outside Linux (fanotify is Linux-only). The agent falls
// back to the periodic FIM scan.
type FIMWatcher struct{}

// StartFIMWatch always fails off Linux.
func StartFIMWatch() (*FIMWatcher, error) {
	return nil, errors.New("fanotify FIM watcher is Linux-only")
}

func (w *FIMWatcher) SetPaths([]string) {}
func (w *FIMWatcher) Drain() []string   { return nil }
func (w *FIMWatcher) Close() error      { return nil }
