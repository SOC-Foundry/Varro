package collect

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// detectCloud probes the well-known cloud metadata endpoints once at startup.
// Each is on the link-local 169.254.169.254 address (or an alias) and returns
// fast or not at all, so a short timeout keeps non-cloud hosts cheap.
func detectCloud(ctx context.Context) *model.CloudInfo {
	if ci := detectGCP(ctx); ci != nil {
		return ci
	}
	if ci := detectAWS(ctx); ci != nil {
		return ci
	}
	if ci := detectAzure(ctx); ci != nil {
		return ci
	}
	return nil
}

func metaGET(ctx context.Context, url string, headers map[string]string) string {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(b))
}

func detectGCP(ctx context.Context) *model.CloudInfo {
	h := map[string]string{"Metadata-Flavor": "Google"}
	base := "http://metadata.google.internal/computeMetadata/v1"
	id := metaGET(ctx, base+"/instance/id", h)
	if id == "" {
		return nil
	}
	ci := &model.CloudInfo{Provider: "gcp", InstanceID: id}
	ci.AccountID = metaGET(ctx, base+"/project/project-id", h)
	// zone comes back as projects/NNN/zones/us-central1-a
	if z := metaGET(ctx, base+"/instance/zone", h); z != "" {
		ci.Zone = z[strings.LastIndexByte(z, '/')+1:]
		if i := strings.LastIndexByte(ci.Zone, '-'); i > 0 {
			ci.Region = ci.Zone[:i]
		}
	}
	if mt := metaGET(ctx, base+"/instance/machine-type", h); mt != "" {
		ci.InstanceType = mt[strings.LastIndexByte(mt, '/')+1:]
	}
	ci.Identity = metaGET(ctx, base+"/instance/service-accounts/default/email", h)
	return ci
}

func detectAWS(ctx context.Context) *model.CloudInfo {
	// IMDSv2: get a token, then read with it.
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	treq, err := http.NewRequestWithContext(tctx, http.MethodPut,
		"http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return nil
	}
	treq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	tresp, err := http.DefaultClient.Do(treq)
	if err != nil {
		return nil
	}
	tb, _ := io.ReadAll(io.LimitReader(tresp.Body, 4096))
	tresp.Body.Close()
	token := strings.TrimSpace(string(tb))
	h := map[string]string{"X-aws-ec2-metadata-token": token}

	base := "http://169.254.169.254/latest/meta-data"
	id := metaGET(ctx, base+"/instance-id", h)
	if id == "" {
		return nil
	}
	ci := &model.CloudInfo{Provider: "aws", InstanceID: id}
	ci.Zone = metaGET(ctx, base+"/placement/availability-zone", h)
	ci.Region = metaGET(ctx, base+"/placement/region", h)
	ci.InstanceType = metaGET(ctx, base+"/instance-type", h)
	ci.Identity = metaGET(ctx, base+"/iam/security-credentials/", h)
	ci.AccountID = metaGET(ctx,
		"http://169.254.169.254/latest/dynamic/instance-identity/document", h)
	return ci
}

func detectAzure(ctx context.Context) *model.CloudInfo {
	h := map[string]string{"Metadata": "true"}
	base := "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"
	// Azure returns JSON; a couple of targeted field reads keep it simple.
	raw := metaGET(ctx, base, h)
	if raw == "" || !strings.Contains(raw, "vmId") {
		return nil
	}
	field := func(key string) string {
		k := `"` + key + `":"`
		i := strings.Index(raw, k)
		if i < 0 {
			return ""
		}
		rest := raw[i+len(k):]
		return rest[:strings.IndexByte(rest, '"')]
	}
	return &model.CloudInfo{
		Provider:     "azure",
		InstanceID:   field("vmId"),
		AccountID:    field("subscriptionId"),
		Region:       field("location"),
		InstanceType: field("vmSize"),
	}
}
