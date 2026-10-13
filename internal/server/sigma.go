package server

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
	yaml "go.yaml.in/yaml/v3"
)

// Sigma import is a pragmatic subset: title, level, tags (MITRE), logsource
// category (→ stream), and a single detection selection (map of field→value(s),
// AND across fields, OR within a list). Conditions beyond one selection are
// imported best-effort with a warning.

type sigmaDoc struct {
	Title     string                 `yaml:"title"`
	Level     string                 `yaml:"level"`
	Tags      []string               `yaml:"tags"`
	Logsource map[string]string      `yaml:"logsource"`
	Detection map[string]interface{} `yaml:"detection"`
}

// Sigma field name (lowercased) → Varro doc field, per stream.
var sigmaFieldMap = map[string]map[string]string{
	model.DetStreamProcess: {
		"image": "image", "originalfilename": "image", "commandline": "command", "user": "user",
	},
	model.DetStreamConnection: {
		"image": "image", "destinationip": "dest", "destinationhostname": "domain",
		"destinationport": "port",
	},
	model.DetStreamListener: {
		"image": "image", "destinationport": "port", "localport": "port",
	},
}

var sigmaTag = regexp.MustCompile(`(?i)^attack\.(t\d{4}(?:\.\d{3})?)$`)

// ParseSigma converts a Sigma YAML rule into a DetectionRule plus any warnings
// about parts that couldn't be represented.
func ParseSigma(src string) (model.DetectionRule, []string, error) {
	var doc sigmaDoc
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		return model.DetectionRule{}, nil, fmt.Errorf("invalid YAML: %w", err)
	}
	var warn []string
	r := model.DetectionRule{Source: "sigma", Enabled: true}
	r.Name = strings.TrimSpace(doc.Title)
	if r.Name == "" {
		return r, nil, fmt.Errorf("rule has no title")
	}
	r.Severity = sigmaLevel(doc.Level)
	for _, t := range doc.Tags {
		if m := sigmaTag.FindStringSubmatch(strings.TrimSpace(t)); m != nil {
			r.MITRE = strings.ToUpper(m[1])
			break
		}
	}
	r.Stream = sigmaStream(doc.Logsource["category"])
	if doc.Logsource["category"] != "" && r.Stream == model.DetStreamProcess &&
		doc.Logsource["category"] != "process_creation" {
		warn = append(warn, "logsource category "+doc.Logsource["category"]+" not directly supported; matching against process events")
	}
	if doc.Detection == nil {
		return r, warn, fmt.Errorf("rule has no detection block")
	}

	// Choose the selection to convert.
	condStr, _ := doc.Detection["condition"].(string)
	selNames := []string{}
	for k := range doc.Detection {
		if k != "condition" {
			selNames = append(selNames, k)
		}
	}
	if len(selNames) == 0 {
		return r, warn, fmt.Errorf("detection has no selection")
	}
	chosen := selNames[0]
	for _, n := range selNames {
		if strings.Contains(condStr, n) {
			chosen = n
			break
		}
	}
	if condStr != "" && condStr != chosen {
		warn = append(warn, "condition \""+condStr+"\" simplified to selection \""+chosen+"\" (AND of its fields)")
	}

	sel, ok := doc.Detection[chosen].(map[string]interface{})
	if !ok {
		// keyword list selection (free-text) → match command/image contains.
		if list, isList := doc.Detection[chosen].([]interface{}); isList {
			f := map[string]string{model.DetStreamProcess: "command", model.DetStreamConnection: "domain", model.DetStreamListener: "image"}[r.Stream]
			r.Conditions = append(r.Conditions, model.DetCond{Field: f, Op: "contains", Values: toStrings(list)})
			warn = append(warn, "keyword selection matched against "+f)
			return r, warn, nil
		}
		return r, warn, fmt.Errorf("selection %q is not a field map", chosen)
	}

	fm := sigmaFieldMap[r.Stream]
	for key, val := range sel {
		parts := strings.Split(key, "|")
		field := strings.ToLower(parts[0])
		mapped, ok := fm[field]
		if !ok {
			warn = append(warn, "field \""+parts[0]+"\" not supported for "+r.Stream+" events; skipped")
			continue
		}
		op := "equals"
		for _, mod := range parts[1:] {
			switch strings.ToLower(mod) {
			case "contains":
				op = "contains"
			case "startswith":
				op = "startswith"
			case "endswith":
				op = "endswith"
			case "re":
				op = "regex"
			case "all":
				warn = append(warn, "modifier |all on "+parts[0]+" treated as OR")
			default:
				warn = append(warn, "modifier |"+mod+" on "+parts[0]+" ignored")
			}
		}
		var values []string
		switch v := val.(type) {
		case []interface{}:
			values = toStrings(v)
		default:
			values = []string{fmt.Sprintf("%v", v)}
		}
		if len(values) == 0 {
			continue
		}
		r.Conditions = append(r.Conditions, model.DetCond{Field: mapped, Op: op, Values: values})
	}
	if len(r.Conditions) == 0 {
		return r, warn, fmt.Errorf("no supported fields in selection %q (fields available for %s: %s)", chosen, r.Stream, strings.Join(fieldsFor(r.Stream), ", "))
	}
	return r, warn, nil
}

func sigmaLevel(l string) string {
	switch strings.ToLower(strings.TrimSpace(l)) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "low", "informational":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

func sigmaStream(cat string) string {
	switch strings.ToLower(strings.TrimSpace(cat)) {
	case "network_connection", "firewall", "dns", "proxy":
		return model.DetStreamConnection
	default:
		return model.DetStreamProcess
	}
}

func toStrings(list []interface{}) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		out = append(out, fmt.Sprintf("%v", v))
	}
	return out
}

func fieldsFor(stream string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range sigmaFieldMap[stream] {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
