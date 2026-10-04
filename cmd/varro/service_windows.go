//go:build windows

package main

import (
	"context"

	"golang.org/x/sys/windows/svc"
)

// isWindowsService reports whether we were started by the Windows Service
// Control Manager rather than a console.
func isWindowsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// runAsService runs fn under the SCM lifecycle: reports Running, cancels fn's
// context on Stop/Shutdown, and waits for it to finish.
func runAsService(ctx context.Context, name string, fn func(context.Context) error) error {
	return svc.Run(name, &scmHandler{ctx: ctx, fn: fn})
}

type scmHandler struct {
	ctx context.Context
	fn  func(context.Context) error
}

func (h *scmHandler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- h.fn(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}
