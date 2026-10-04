package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/soc-foundry/varro/internal/model"
)

// runActions fetches and executes any pending response actions. Only
// allowlisted action types are ever run; there is no path to execute an
// operator-supplied command string.
func (a *Agent) runActions(ctx context.Context, actions []model.Action) {
	for _, act := range actions {
		ok, result := a.execAction(ctx, act)
		a.ackAction(ctx, act.ID, ok, result)
		a.log.Info("executed response action", "type", act.Type, "arg", act.Arg, "ok", ok, "result", result)
	}
}

func (a *Agent) execAction(ctx context.Context, act model.Action) (bool, string) {
	switch act.Type {
	case model.ActionKillProcess:
		pid, err := strconv.Atoi(act.Arg)
		if err != nil || pid <= 1 { // never target init/kernel
			return false, "invalid pid"
		}
		p, err := process.NewProcessWithContext(ctx, int32(pid))
		if err != nil {
			return false, "no such process"
		}
		name, _ := p.NameWithContext(ctx)
		if err := p.KillWithContext(ctx); err != nil {
			return false, "kill failed: " + err.Error()
		}
		return true, fmt.Sprintf("killed pid %d (%s)", pid, name)

	case model.ActionIsolate:
		if err := isolateHost(ctx, a.cfg.ServerURL); err != nil {
			return false, "isolate failed: " + err.Error()
		}
		return true, "host isolated (collector channel preserved)"

	case model.ActionUnisolate:
		if err := unisolateHost(ctx); err != nil {
			return false, "unisolate failed: " + err.Error()
		}
		return true, "isolation lifted"

	default:
		// Defense in depth: the server validates too, but the agent is the
		// final authority on what it will run.
		return false, "unsupported action type: " + act.Type
	}
}

// fetchActions claims this agent's pending actions from the collector.
func (a *Agent) fetchActions(ctx context.Context) []model.Action {
	req, err := a.authedRequest(ctx, http.MethodGet, "/api/v1/agent/actions", nil)
	if err != nil {
		return nil
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out []model.Action
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil
	}
	return out
}

func (a *Agent) ackAction(ctx context.Context, id int64, ok bool, result string) {
	body, _ := json.Marshal(map[string]any{"ok": ok, "result": result})
	req, err := a.authedRequest(ctx, http.MethodPost,
		fmt.Sprintf("/api/v1/actions/%d/ack", id), body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := a.client.Do(req); err == nil {
		resp.Body.Close()
	}
}
