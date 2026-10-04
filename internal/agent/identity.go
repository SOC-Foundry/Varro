package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const agentIDFile = "agent-id"

// Linux machine-id locations, privilege-independent and stable for the life
// of the OS install.
var machineIDPaths = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}

// resolveAgentID determines this endpoint's stable identity and persists it,
// so the answer never changes for the life of the state directory:
//
//  1. A previously persisted agent-id wins unconditionally.
//  2. An agent enrolled before agent-id files existed keeps its legacy
//     (gopsutil host ID) identity so upgrading doesn't create a ghost
//     endpoint.
//  3. Fresh installs use the OS machine-id, which unlike the legacy
//     derivation does not depend on whether the agent runs as root.
func resolveAgentID(stateDir, legacyID string) (string, error) {
	idPath := filepath.Join(stateDir, agentIDFile)
	if b, err := os.ReadFile(idPath); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}

	var id string
	if _, err := os.Stat(filepath.Join(stateDir, tokenFile)); err == nil {
		id = legacyID
	} else {
		id = machineID()
		if id == "" {
			id = legacyID
		}
	}
	if id == "" {
		id, _ = os.Hostname()
	}
	if id == "" {
		return "", fmt.Errorf("cannot determine a stable agent identity")
	}
	if err := os.WriteFile(idPath, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("persist agent id: %w", err)
	}
	return id, nil
}

func machineID() string {
	for _, p := range machineIDPaths {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}
