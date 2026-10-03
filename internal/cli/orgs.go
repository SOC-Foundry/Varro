package cli

import (
	"context"
	"flag"
	"fmt"
	"net/url"

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
	fs.Parse(rest)
	if name == "" {
		return fmt.Errorf("usage: varro org-create <name> [--server URL] [--token TOKEN]")
	}

	var org model.Org
	if err := postJSON(ctx, *base, *token, "/api/v1/orgs", map[string]string{"name": name}, &org); err != nil {
		return err
	}
	fmt.Printf("org created: %s (id %s)\n", org.Name, org.ID)
	fmt.Printf("next: varro org-token %s   # mint an enrollment token for its agents\n", org.ID)
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
	fs.Parse(rest)
	if ref == "" || email == "" {
		return fmt.Errorf("usage: varro org-invite <org-id-or-name> <email>")
	}

	if err := postJSON(ctx, *base, *token, "/api/v1/orgs/"+url.PathEscape(ref)+"/members",
		map[string]string{"email": email}, nil); err != nil {
		return err
	}
	fmt.Printf("%s invited to org %s — they'll see it on next Google sign-in\n", email, ref)
	return nil
}
