package server

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

// atkTech is one technique in the curated catalog.
type atkTech struct{ id, name string }

// attackCatalog is a curated, endpoint-relevant slice of the ATT&CK Enterprise
// matrix (not the full ~600-technique matrix) — the universe Varro measures its
// detection coverage against, grouped by tactic in matrix order. Techniques Varro
// already references are included; the rest make coverage gaps visible.
var attackCatalog = []struct {
	tactic string
	techs  []atkTech
}{
	{"Initial Access", []atkTech{{"T1190", "Exploit Public-Facing Application"}, {"T1078", "Valid Accounts"}}},
	{"Execution", []atkTech{{"T1059", "Command & Scripting Interpreter"}, {"T1204", "User Execution"}, {"T1053", "Scheduled Task/Job"}, {"T1569", "System Services"}}},
	{"Persistence", []atkTech{{"T1543", "Create or Modify System Process"}, {"T1547", "Boot/Logon Autostart"}, {"T1136", "Create Account"}, {"T1504", "PowerShell Profile"}}},
	{"Privilege Escalation", []atkTech{{"T1548", "Abuse Elevation Control"}, {"T1068", "Exploitation for Priv-Esc"}, {"T1055", "Process Injection"}}},
	{"Defense Evasion", []atkTech{{"T1070", "Indicator Removal"}, {"T1562", "Impair Defenses"}, {"T1036", "Masquerading"}, {"T1027", "Obfuscated Files/Info"}}},
	{"Credential Access", []atkTech{{"T1110", "Brute Force"}, {"T1003", "OS Credential Dumping"}, {"T1552", "Unsecured Credentials"}}},
	{"Discovery", []atkTech{{"T1046", "Network Service Discovery"}, {"T1057", "Process Discovery"}, {"T1518", "Software Discovery"}, {"T1082", "System Information Discovery"}, {"T1083", "File & Directory Discovery"}}},
	{"Lateral Movement", []atkTech{{"T1021", "Remote Services"}, {"T1570", "Lateral Tool Transfer"}}},
	{"Collection", []atkTech{{"T1005", "Data from Local System"}, {"T1056", "Input Capture"}}},
	{"Command & Control", []atkTech{{"T1071", "Application Layer Protocol"}, {"T1105", "Ingress Tool Transfer"}, {"T1571", "Non-Standard Port"}, {"T1573", "Encrypted Channel"}}},
	{"Exfiltration", []atkTech{{"T1041", "Exfil Over C2 Channel"}, {"T1048", "Exfil Over Alt Protocol"}}},
	{"Impact", []atkTech{{"T1496", "Resource Hijacking"}, {"T1486", "Data Encrypted for Impact"}, {"T1489", "Service Stop"}, {"T1490", "Inhibit System Recovery"}}},
}

var techniqueRe = regexp.MustCompile(`T1[0-9]{3}(?:\.[0-9]{3})?`)

// parentTechnique strips a sub-technique suffix (T1059.004 → T1059) so coverage
// matches at the technique level.
func parentTechnique(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return id
}

// extractTechniques pulls all ATT&CK technique IDs from a free-text MITRE field.
func extractTechniques(s string) []string {
	return techniqueRe.FindAllString(s, -1)
}

// handleAttackCoverage returns the detection-coverage map for the request scope:
// which catalog techniques are covered by currently-enabled detections (built-in +
// custom/Sigma rules), grouped by tactic. Read-scoped.
func (s *Server) handleAttackCoverage(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	orgs := scope
	if orgs == nil {
		if all, err := s.store.Orgs(r.Context()); err == nil {
			for _, o := range all {
				orgs = append(orgs, o.ID)
			}
		}
	}

	// parent technique ID -> set of covering rule names (across the scope's orgs).
	covered := map[string]map[string]bool{}
	add := func(mitre, rule string) {
		for _, raw := range extractTechniques(mitre) {
			p := parentTechnique(raw)
			if covered[p] == nil {
				covered[p] = map[string]bool{}
			}
			covered[p][rule] = true
		}
	}
	for _, org := range orgs {
		settings, _ := s.store.DetectionSettings(r.Context(), org)
		for _, b := range builtinDetections {
			enabled := true
			if st, ok := settings[b.Name]; ok {
				enabled = st.Enabled
			}
			if enabled {
				add(b.MITRE, b.Name)
			}
		}
		rules, _ := s.store.DetectionRules(r.Context(), org)
		for _, rl := range rules {
			if rl.Enabled {
				add(rl.MITRE, ruleLabel(rl))
			}
		}
	}

	rulesFor := func(id string) []string {
		var out []string
		for name := range covered[id] {
			out = append(out, name)
		}
		return out
	}

	var out model.AttackCoverage
	inCatalog := map[string]bool{}
	for _, grp := range attackCatalog {
		t := model.AttackTactic{Tactic: grp.tactic}
		for _, tech := range grp.techs {
			inCatalog[tech.id] = true
			c := len(covered[tech.id]) > 0
			t.Techniques = append(t.Techniques, model.AttackTechnique{ID: tech.id, Name: tech.name, Covered: c, Rules: rulesFor(tech.id)})
			t.Total++
			out.TotalTechniques++
			if c {
				t.Covered++
				out.CoveredTechniques++
			}
		}
		out.Tactics = append(out.Tactics, t)
	}
	// Techniques covered by rules but outside the curated catalog → an "Other" group,
	// so nothing a rule actually covers is hidden.
	var other model.AttackTactic
	other.Tactic = "Other"
	for id := range covered {
		if inCatalog[id] {
			continue
		}
		other.Techniques = append(other.Techniques, model.AttackTechnique{ID: id, Name: "(uncatalogued)", Covered: true, Rules: rulesFor(id)})
		other.Covered++
		other.Total++
		out.CoveredTechniques++
		out.TotalTechniques++
	}
	if len(other.Techniques) > 0 {
		out.Tactics = append(out.Tactics, other)
	}
	writeJSON(w, out)
}

// ruleLabel names a custom/Sigma rule for the coverage view.
func ruleLabel(r model.DetectionRule) string {
	if r.Source == "sigma" {
		return "sigma:" + r.Name
	}
	return "custom:" + r.Name
}
