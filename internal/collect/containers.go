package collect

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// Docker/Podman API socket locations, tried in order.
var dockerSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/podman/podman.sock",
}

const maxContainerEvents = 20

// dockerClient is an HTTP client bound to the container runtime's unix socket.
// nil when no runtime is present.
func (c *Collector) dockerClient() *http.Client {
	for _, sock := range dockerSockets {
		if _, err := net.Dial("unix", sock); err == nil {
			s := sock
			return &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "unix", s)
					},
				},
			}
		}
	}
	return nil
}

type dockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
}

// sampleContainers enumerates running containers and emits start/stop events.
func (c *Collector) sampleContainers(ctx context.Context, snap *model.Snapshot) {
	client := c.dockerClient()
	if client == nil {
		return
	}
	// The Docker API is served over HTTP on the unix socket; host is ignored.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var dcs []dockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&dcs); err != nil {
		return
	}

	current := map[string]bool{}
	for _, dc := range dcs {
		name := ""
		if len(dc.Names) > 0 {
			name = strings.TrimPrefix(dc.Names[0], "/")
		}
		ci := model.ContainerInfo{
			ID:     shortID(dc.ID),
			Name:   name,
			Image:  dc.Image,
			Status: dc.Status,
			// Kubernetes stamps these labels on every pod container.
			Pod:       dc.Labels["io.kubernetes.pod.name"],
			Namespace: dc.Labels["io.kubernetes.pod.namespace"],
		}
		// A k8s pod container's own name is clearer than the mangled docker name.
		if kn := dc.Labels["io.kubernetes.container.name"]; kn != "" {
			ci.Name = kn
		}
		snap.Containers = append(snap.Containers, ci)
		current[ci.ID] = true

		if c.prevContainers != nil && !c.prevContainers[ci.ID] {
			msg := "container started: " + ci.Name + " (" + ci.Image + ")"
			if ci.Pod != "" {
				msg += " pod " + ci.Namespace + "/" + ci.Pod
			}
			snap.Events = append(snap.Events, model.Event{Type: model.EventContainerNew, Message: msg})
		}
	}
	if c.prevContainers != nil {
		n := 0
		for id := range c.prevContainers {
			if !current[id] && n < maxContainerEvents {
				snap.Events = append(snap.Events, model.Event{
					Type: model.EventContainerGone, Message: "container stopped: " + id,
				})
				n++
			}
		}
	}
	c.prevContainers = current
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
