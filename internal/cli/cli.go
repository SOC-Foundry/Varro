// Package cli implements the query commands that talk to a Varro collector:
// endpoints, status, and top.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func getJSON(ctx context.Context, base, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%s returned 401 — this collector requires auth; pass --token (master or org enrollment token)", base+path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", base+path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func postJSON(ctx context.Context, base, token, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", base+path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func putJSON(ctx context.Context, base, token, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s returned %s: %s", base+path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func doDelete(ctx context.Context, base, token, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, base+path, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", base+path, resp.Status)
	}
	return nil
}

func serverFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("VARRO_SERVER")
	if def == "" {
		def = "http://localhost:9477"
	}
	return fs.String("server", def, "collector base URL")
}

func tokenFlag(fs *flag.FlagSet) *string {
	return fs.String("token", os.Getenv("VARRO_TOKEN"),
		"bearer token (master or org enrollment token; needed when auth is enabled)")
}

// resolveEndpoint turns a user-supplied name (ID, hostname, or hostname
// prefix) into an endpoint ID. With no name and exactly one endpoint, that
// endpoint is used.
func resolveEndpoint(ctx context.Context, base, token, name string) (model.EndpointSummary, error) {
	var eps []model.EndpointSummary
	if err := getJSON(ctx, base, token, "/api/v1/endpoints", &eps); err != nil {
		return model.EndpointSummary{}, err
	}
	if len(eps) == 0 {
		return model.EndpointSummary{}, fmt.Errorf("the collector has no endpoints yet")
	}
	if name == "" {
		if len(eps) == 1 {
			return eps[0], nil
		}
		var names []string
		for _, ep := range eps {
			names = append(names, ep.Hostname)
		}
		return model.EndpointSummary{}, fmt.Errorf("multiple endpoints, specify one of: %s", strings.Join(names, ", "))
	}
	var prefix []model.EndpointSummary
	for _, ep := range eps {
		if ep.ID == name || ep.Hostname == name {
			return ep, nil
		}
		if strings.HasPrefix(ep.Hostname, name) {
			prefix = append(prefix, ep)
		}
	}
	if len(prefix) == 1 {
		return prefix[0], nil
	}
	return model.EndpointSummary{}, fmt.Errorf("no endpoint matches %q", name)
}

// splitArgs separates a leading positional endpoint name from flags.
func splitArgs(args []string) (name string, rest []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func fmtBytes(n float64, suffix string) string {
	units := []string{"", "K", "M", "G", "T"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s%s", n, units[i], suffix)
	}
	return fmt.Sprintf("%.1f %s%s", n, units[i], suffix)
}

// Endpoints lists all endpoints known to the collector.
func Endpoints(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("endpoints", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	fs.Parse(args)

	var eps []model.EndpointSummary
	if err := getJSON(ctx, *base, *token, "/api/v1/endpoints", &eps); err != nil {
		return err
	}
	if len(eps) == 0 {
		fmt.Println("no endpoints have reported yet")
		return nil
	}
	fmt.Printf("%-22s %-10s %-8s %-14s %-8s %-6s %6s %6s   %s\n",
		"HOSTNAME", "ORG", "STATE", "PLATFORM", "AGENT", "CORES", "CPU%", "MEM%", "LAST SEEN")
	for _, ep := range eps {
		state := "offline"
		if ep.Online {
			state = "online"
		}
		fmt.Printf("%-22s %-10s %-8s %-14s %-8s %-6d %6.1f %6.1f   %s\n",
			ep.Hostname, ep.OrgID, state, ep.Platform, ep.AgentVersion, ep.Cores,
			ep.CPUPercent, ep.MemPercent, ep.LastSeen.Local().Format("2006-01-02 15:04:05"))
	}
	return nil
}

// Status prints the latest snapshot of one endpoint.
func Status(ctx context.Context, args []string) error {
	name, rest := splitArgs(args)
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	fs.Parse(rest)

	ep, err := resolveEndpoint(ctx, *base, *token, name)
	if err != nil {
		return err
	}
	var snap model.Snapshot
	if err := getJSON(ctx, *base, *token, "/api/v1/endpoints/"+url.PathEscape(ep.ID)+"/latest", &snap); err != nil {
		return err
	}

	fmt.Printf("%s  (%s %s, %s)\n", snap.Hostname, snap.Host.Platform, snap.Host.PlatformVersion, snap.Host.Arch)
	fmt.Printf("  sampled   %s\n", snap.Timestamp.Local().Format(time.RFC1123))
	fmt.Printf("  uptime    %s\n", (time.Duration(snap.Host.Uptime) * time.Second).Truncate(time.Minute))
	fmt.Printf("  cpu       %.1f%% of %d cores   load %.2f %.2f %.2f\n",
		snap.CPU.TotalPercent, snap.CPU.Cores, snap.CPU.Load1, snap.CPU.Load5, snap.CPU.Load15)
	fmt.Printf("  memory    %s / %s (%.1f%%)   swap %s / %s\n",
		fmtBytes(float64(snap.Memory.Used), "B"), fmtBytes(float64(snap.Memory.Total), "B"),
		snap.Memory.UsedPercent,
		fmtBytes(float64(snap.Memory.SwapUsed), "B"), fmtBytes(float64(snap.Memory.SwapTotal), "B"))
	fmt.Printf("  network   ▼ %s  ▲ %s\n",
		fmtBytes(snap.Network.RxRate, "B/s"), fmtBytes(snap.Network.TxRate, "B/s"))
	for _, d := range snap.Disks {
		fmt.Printf("  disk      %-20s %s / %s (%.0f%%)\n", d.Mountpoint,
			fmtBytes(float64(d.Used), "B"), fmtBytes(float64(d.Total), "B"), d.UsedPercent)
	}
	fmt.Printf("  procs     %d running\n", snap.Host.NumProcs)
	return nil
}

// Top shows a live-updating view of one endpoint, like a remote htop.
func Top(ctx context.Context, args []string) error {
	name, rest := splitArgs(args)
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	interval := fs.Duration("interval", 2*time.Second, "refresh interval")
	fs.Parse(rest)

	ep, err := resolveEndpoint(ctx, *base, *token, name)
	if err != nil {
		return err
	}

	// Alternate screen buffer so the user's scrollback is preserved.
	fmt.Print("\x1b[?1049h\x1b[?25l")
	defer fmt.Print("\x1b[?1049l\x1b[?25h")

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		var snap model.Snapshot
		if err := getJSON(ctx, *base, *token, "/api/v1/endpoints/"+url.PathEscape(ep.ID)+"/latest", &snap); err == nil {
			renderTop(&snap)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func gauge(pct float64, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100 * float64(width))
	color := "\x1b[32m" // green
	if pct > 85 {
		color = "\x1b[31m" // red
	} else if pct > 60 {
		color = "\x1b[33m" // yellow
	}
	return color + strings.Repeat("|", filled) + "\x1b[90m" + strings.Repeat("·", width-filled) + "\x1b[0m"
}

func renderTop(s *model.Snapshot) {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J")
	fmt.Fprintf(&b, "\x1b[1m%s\x1b[0m  %s %s · up %s · load %.2f %.2f %.2f · %s\n\n",
		s.Hostname, s.Host.Platform, s.Host.PlatformVersion,
		(time.Duration(s.Host.Uptime)*time.Second).Truncate(time.Minute),
		s.CPU.Load1, s.CPU.Load5, s.CPU.Load15,
		s.Timestamp.Local().Format("15:04:05"))

	fmt.Fprintf(&b, "  CPU %5.1f%%  [%s]\n", s.CPU.TotalPercent, gauge(s.CPU.TotalPercent, 50))
	fmt.Fprintf(&b, "  MEM %5.1f%%  [%s]  %s / %s\n", s.Memory.UsedPercent, gauge(s.Memory.UsedPercent, 50),
		fmtBytes(float64(s.Memory.Used), "B"), fmtBytes(float64(s.Memory.Total), "B"))
	fmt.Fprintf(&b, "  NET ▼ %-12s ▲ %-12s\n\n",
		fmtBytes(s.Network.RxRate, "B/s"), fmtBytes(s.Network.TxRate, "B/s"))

	fmt.Fprintf(&b, "\x1b[7m%7s %-24s %-12s %7s %7s %10s\x1b[0m\n",
		"PID", "NAME", "USER", "CPU%", "MEM%", "RSS")
	for i, p := range s.Processes {
		if i >= 25 {
			break
		}
		name := p.Name
		if len(name) > 24 {
			name = name[:24]
		}
		user := p.Username
		if len(user) > 12 {
			user = user[:12]
		}
		fmt.Fprintf(&b, "%7d %-24s %-12s %7.1f %7.1f %10s\n",
			p.PID, name, user, p.CPUPercent, p.MemPercent, fmtBytes(float64(p.RSS), "B"))
	}
	os.Stdout.WriteString(b.String())
}
