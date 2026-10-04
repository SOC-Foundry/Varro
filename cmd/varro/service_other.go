//go:build !windows

package main

import "context"

func isWindowsService() bool { return false }

func runAsService(context.Context, string, func(context.Context) error) error {
	panic("runAsService is windows-only")
}
