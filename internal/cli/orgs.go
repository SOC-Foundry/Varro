package cli

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

// Orgs lists organizations (admin).
func Orgs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("orgs", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	fs.Parse(args)

	var orgs []model.Org
	if err := getJSON(ctx, *base, *token, "/api/v1/orgs", &orgs); err != nil {
		return err
	}
	fmt.Printf("%-14s %-30s %s\n", "ID", "NAME", "CREATED")
	for _, o := range orgs {
		fmt.Printf("%-14s %-30s %s\n", o.ID, o.Name, o.CreatedAt.Local().Format("2006-01-02 15:04"))
	}
	return nil
}

// OrgCreate makes a new org (admin).
func OrgCreate(ctx context.Context, args []string) error {
	name, rest := splitArgs(args)
	fs := flag.NewFlagSet("org-create", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	domain := fs.String("domain", "", "auto-join email domain (anyone @domain becomes a member at sign-in)")
	fs.Parse(rest)
	if name == "" {
		return fmt.Errorf("usage: varro org-create <name> [--domain example.com]")
	}

	var org model.Org
	if err := postJSON(ctx, *base, *token, "/api/v1/orgs",
		map[string]string{"name": name, "auto_join_domain": *domain}, &org); err != nil {
		return err
	}
	fmt.Printf("org created: %s (id %s)\n", org.Name, org.ID)
	if org.AutoJoinDomain != "" {
		fmt.Printf("auto-join: anyone signing in @%s becomes a member\n", org.AutoJoinDomain)
	}
	fmt.Printf("next: varro org-token %s   # mint an enrollment token for its agents\n", org.ID)
	return nil
}

// Onboard sets up a new customer in one shot: org, admin user, enrollment
// token, and ready-to-send install commands.
func Onboard(ctx context.Context, args []string) error {
	name, rest := splitArgs(args)
	var email string
	if len(rest) > 0 && rest[0][0] != '-' {
		email, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("onboard", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	domain := fs.String("domain", "", "auto-join email domain for their whole team")
	fs.Parse(rest)
	if name == "" || email == "" {
		return fmt.Errorf("usage: varro onboard <org-name> <admin-email> [--domain example.com]")
	}

	var org model.Org
	if err := postJSON(ctx, *base, *token, "/api/v1/orgs",
		map[string]string{"name": name, "auto_join_domain": *domain}, &org); err != nil {
		return fmt.Errorf("create org: %w", err)
	}
	if err := postJSON(ctx, *base, *token, "/api/v1/orgs/"+url.PathEscape(org.ID)+"/members",
		map[string]string{"email": email, "role": "admin"}, nil); err != nil {
		return fmt.Errorf("invite admin: %w", err)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := postJSON(ctx, *base, *token, "/api/v1/orgs/"+url.PathEscape(org.ID)+"/tokens",
		map[string]string{"name": "initial"}, &tok); err != nil {
		return fmt.Errorf("mint token: %w", err)
	}

	fmt.Printf(`org onboarded: %s (id %s)

org admin:  %s  (invitation email sent if SMTP is configured)
sign-in:    %s
`, org.Name, org.ID, email, *base)
	if org.AutoJoinDomain != "" {
		fmt.Printf("auto-join:  anyone signing in @%s becomes a member automatically\n", org.AutoJoinDomain)
	}
	fmt.Printf(`
enrollment token (shown once):

  %s

install agents:
  Linux:    curl -sSL %s/install.sh | sudo VARRO_TOKEN=%s sh
  Windows:  $env:VARRO_TOKEN = "%s"; iwr -UseBasicParsing %s/install.ps1 | iex
  macOS:    curl -sSL %s/install.sh | sudo VARRO_TOKEN=%s sh
`, tok.Token, *base, tok.Token, tok.Token, *base, *base, tok.Token)
	return nil
}

// OrgToken mints an enrollment token for an org (admin). Shown once.
func OrgToken(ctx context.Context, args []string) error {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("org-token", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	name := fs.String("name", "", "label for this token (e.g. \"site-berlin\")")
	fs.Parse(rest)
	if ref == "" {
		return fmt.Errorf("usage: varro org-token <org-id-or-name> [--name LABEL]")
	}

	var out struct {
		OrgID string `json:"org_id"`
		Token string `json:"token"`
	}
	if err := postJSON(ctx, *base, *token, "/api/v1/orgs/"+url.PathEscape(ref)+"/tokens",
		map[string]string{"name": *name}, &out); err != nil {
		return err
	}
	fmt.Printf("enrollment token for org %s (shown once, store it safely):\n\n  %s\n\n", out.OrgID, out.Token)
	fmt.Printf("agents join with:\n  varro agent --server %s --token %s\n", *base, out.Token)
	return nil
}

// Inventory shows an endpoint's installed software.
func Inventory(ctx context.Context, args []string) error {
	name, rest := splitArgs(args)
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	grep := fs.String("grep", "", "only show packages whose name contains this")
	fs.Parse(rest)

	ep, err := resolveEndpoint(ctx, *base, *token, name)
	if err != nil {
		return err
	}
	var inv struct {
		CollectedAt  string `json:"collected_at"`
		Kernel       string `json:"kernel"`
		Manager      string `json:"manager"`
		PackageCount int    `json:"package_count"`
		Packages     []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := getJSON(ctx, *base, *token,
		"/api/v1/endpoints/"+url.PathEscape(ep.ID)+"/inventory", &inv); err != nil {
		return err
	}
	fmt.Printf("%s — kernel %s, %d packages (%s), collected %s\n\n",
		ep.Hostname, inv.Kernel, inv.PackageCount, inv.Manager, inv.CollectedAt)
	shown := 0
	for _, p := range inv.Packages {
		if *grep != "" && !strings.Contains(p.Name, *grep) {
			continue
		}
		fmt.Printf("  %-40s %s\n", p.Name, p.Version)
		shown++
	}
	if *grep != "" {
		fmt.Printf("\n%d package(s) matching %q\n", shown, *grep)
	}
	return nil
}

// EndpointRemove deletes a decommissioned endpoint and all of its history
// (admin). Use revoke instead to cut off a machine but keep its data.
func EndpointRemove(ctx context.Context, args []string) error {
	name, rest := splitArgs(args)
	fs := flag.NewFlagSet("endpoint-remove", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	fs.Parse(rest)
	if name == "" {
		return fmt.Errorf("usage: varro endpoint-remove <endpoint> [--server URL] [--token ADMIN]")
	}

	ep, err := resolveEndpoint(ctx, *base, *token, name)
	if err != nil {
		return err
	}
	if err := doDelete(ctx, *base, *token, "/api/v1/endpoints/"+url.PathEscape(ep.ID)); err != nil {
		return err
	}
	fmt.Printf("endpoint %s (%s) and all its data removed\n", ep.Hostname, ep.ID)
	return nil
}

// OrgRemoveMember drops a member from an org (admin).
func OrgRemoveMember(ctx context.Context, args []string) error {
	ref, rest := splitArgs(args)
	var email string
	if len(rest) > 0 && rest[0][0] != '-' {
		email, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("org-remove-member", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	fs.Parse(rest)
	if ref == "" || email == "" {
		return fmt.Errorf("usage: varro org-remove-member <org-id-or-name> <email>")
	}

	if err := doDelete(ctx, *base, *token,
		"/api/v1/orgs/"+url.PathEscape(ref)+"/members/"+url.PathEscape(email)); err != nil {
		return err
	}
	fmt.Printf("%s removed from org %s — access ends at their next request\n", email, ref)
	return nil
}

// OrgInvite adds a member (by email) to an org (admin).
func OrgInvite(ctx context.Context, args []string) error {
	ref, rest := splitArgs(args)
	var email string
	if len(rest) > 0 && rest[0][0] != '-' {
		email, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("org-invite", flag.ExitOnError)
	base := serverFlag(fs)
	token := tokenFlag(fs)
	role := fs.String("role", "member", "member, or admin (manages this org's members and tokens)")
	fs.Parse(rest)
	if ref == "" || email == "" {
		return fmt.Errorf("usage: varro org-invite <org-id-or-name> <email> [--role admin]")
	}

	if err := postJSON(ctx, *base, *token, "/api/v1/orgs/"+url.PathEscape(ref)+"/members",
		map[string]string{"email": email, "role": *role}, nil); err != nil {
		return err
	}
	fmt.Printf("%s invited to org %s as %s — they'll see it on next Google sign-in\n", email, ref, *role)
	return nil
}
