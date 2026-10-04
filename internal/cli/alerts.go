package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// Alerts lists alerts known to the collector (firing by default).
func Alerts(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("alerts", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	all := fs.Bool("all", false, "include resolved alerts")
	limit := fs.Int("n", 50, "max alerts to show")
	fs.Parse(args)

	state := "firing"
	if *all {
		state = ""
	}
	var alerts []model.Alert
	path := fmt.Sprintf("/api/v1/alerts?state=%s&limit=%d", state, *limit)
	if err := getJSON(ctx, *base, *token, path, &alerts); err != nil {
		return err
	}
	if len(alerts) == 0 {
		fmt.Println("no alerts")
		return nil
	}
	fmt.Printf("%-9s %-20s %-18s %-20s %s\n", "STATE", "RULE", "HOST", "STARTED", "MESSAGE")
	for _, a := range alerts {
		fmt.Printf("%-9s %-20s %-18s %-20s %s\n",
			a.State, a.Rule, a.Hostname,
			a.StartedAt.Local().Format("2006-01-02 15:04:05"), a.Message)
	}
	return nil
}

// Events shows the fleet (or one endpoint's) security/change event feed.
func Events(ctx context.Context, args []string) error {
	name, rest := splitArgs(args)
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	limit := fs.Int("n", 50, "max events to show")
	fs.Parse(rest)

	path := fmt.Sprintf("/api/v1/events?limit=%d", *limit)
	if name != "" {
		ep, err := resolveEndpoint(ctx, *base, *token, name)
		if err != nil {
			return err
		}
		path = fmt.Sprintf("/api/v1/endpoints/%s/events?limit=%d", url.PathEscape(ep.ID), *limit)
	}
	var events []model.StoredEvent
	if err := getJSON(ctx, *base, *token, path, &events); err != nil {
		return err
	}
	if len(events) == 0 {
		fmt.Println("no events")
		return nil
	}
	for _, ev := range events {
		fmt.Printf("%s  %-18s %-17s %s\n",
			ev.Timestamp.Local().Format("2006-01-02 15:04:05"),
			ev.Hostname, ev.Type, ev.Message)
	}
	return nil
}

// Audit prints the administrative audit log.
func Audit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	limit := fs.Int("n", 100, "max entries")
	fs.Parse(args)

	var entries []model.AuditEntry
	if err := getJSON(ctx, *base, *token, fmt.Sprintf("/api/v1/audit?limit=%d", *limit), &entries); err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("no audit entries")
		return nil
	}
	fmt.Printf("%-20s %-26s %-18s %s\n", "WHEN", "ACTOR", "ACTION", "TARGET")
	for _, e := range entries {
		fmt.Printf("%-20s %-26s %-18s %s\n",
			e.Timestamp.Local().Format("2006-01-02 15:04:05"), e.Actor, e.Action, e.Target)
	}
	return nil
}

// Revoke deletes an agent's token so it can no longer ingest (admin action).
func Revoke(ctx context.Context, args []string) error {
	name, rest := splitArgs(args)
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	base := serverFlag(fs)
	token := fs.String("token", os.Getenv("VARRO_TOKEN"), "master (admin) token")
	fs.Parse(rest)
	if name == "" {
		return fmt.Errorf("usage: varro revoke <endpoint> [--server URL] [--token TOKEN]")
	}
	if *token == "" {
		return fmt.Errorf("revoke requires --token (or VARRO_TOKEN)")
	}

	ep, err := resolveEndpoint(ctx, *base, *token, name)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		*base+"/api/v1/endpoints/"+url.PathEscape(ep.ID)+"/token", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke returned %s", resp.Status)
	}
	fmt.Printf("token revoked for %s (%s)\n", ep.Hostname, ep.ID)
	return nil
}
