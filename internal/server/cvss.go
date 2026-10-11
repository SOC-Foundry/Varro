package server

import (
	"math"
	"strings"
)

// normalizeSeverity folds a raw severity — which may be a qualitative label
// (GHSA-style "HIGH"/"MODERATE") or a CVSS vector string (Debian/OSV store the
// vector, not a rating) — into a single lower-case bucket: critical, high,
// medium, low, or unknown. This is what makes the compliance report's
// "by severity" rollup meaningful instead of one bucket per CVSS vector.
func normalizeSeverity(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "unknown"
	}
	// Already a qualitative rating?
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low", "minor", "negligible":
		return "low"
	case "none", "unknown", "unspecified":
		return "unknown"
	}
	// Otherwise treat it as a CVSS vector and score it.
	if score, ok := cvssBaseScore(s); ok {
		return scoreBucket(score)
	}
	return "unknown"
}

// scoreBucket maps a CVSS base score to the standard qualitative rating.
func scoreBucket(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

// cvssBaseScore computes a base score from a CVSS vector string. It handles
// v3.0/v3.1 exactly and approximates v4.0 and v2.0 (full v4 scoring requires a
// large official lookup table; the approximation only needs to land in the
// right qualitative bucket). Returns ok=false if the string isn't a recognized
// vector.
func cvssBaseScore(vec string) (float64, bool) {
	m := parseVector(vec)
	if len(m) == 0 {
		return 0, false
	}
	switch {
	case strings.HasPrefix(vec, "CVSS:3"):
		return cvssV3(m), true
	case strings.HasPrefix(vec, "CVSS:4"):
		return cvssV4Approx(m), true
	case strings.HasPrefix(vec, "CVSS:2") || m["Au"] != "": // v2 has an Au metric
		return cvssV2(m), true
	}
	return 0, false
}

// parseVector splits "CVSS:3.1/AV:N/AC:L/..." into {AV:N, AC:L, ...}. The
// leading "CVSS:x.y" token has no colon-separated metric name we care about, so
// it's skipped.
func parseVector(vec string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(vec, "/") {
		k, v, ok := strings.Cut(part, ":")
		if !ok || k == "CVSS" {
			continue
		}
		out[k] = v
	}
	return out
}

// roundUp implements CVSS v3.1 Roundup: smallest 1-decimal value >= x.
func roundUp(x float64) float64 {
	i := math.Round(x * 100000)
	if math.Mod(i, 10000) == 0 {
		return i / 100000
	}
	return (math.Floor(i/10000) + 1) / 10
}

func cvssV3(m map[string]string) float64 {
	av := pick(m["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac := pick(m["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	ui := pick(m["UI"], map[string]float64{"N": 0.85, "R": 0.62})
	scopeChanged := m["S"] == "C"
	var pr float64
	if scopeChanged {
		pr = pick(m["PR"], map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5})
	} else {
		pr = pick(m["PR"], map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27})
	}
	imp := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, i, a := pick(m["C"], imp), pick(m["I"], imp), pick(m["A"], imp)

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	expl := 8.22 * av * ac * pr * ui
	if scopeChanged {
		return roundUp(math.Min(1.08*(impact+expl), 10))
	}
	return roundUp(math.Min(impact+expl, 10))
}

// cvssV2 computes the CVSS v2.0 base score (standard formula).
func cvssV2(m map[string]string) float64 {
	av := pick(m["AV"], map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0})
	ac := pick(m["AC"], map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71})
	au := pick(m["Au"], map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704})
	cia := map[string]float64{"N": 0, "P": 0.275, "C": 0.660}
	c, i, a := pick(m["C"], cia), pick(m["I"], cia), pick(m["A"], cia)

	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	expl := 20 * av * ac * au
	f := 1.176
	if impact == 0 {
		f = 0
	}
	score := (0.6*impact + 0.4*expl - 1.5) * f
	return math.Round(score*10) / 10
}

// cvssV4Approx approximates a CVSS v4.0 base score. Exact v4 scoring maps a
// six-dimension MacroVector through an official 270-entry lookup table; here we
// reuse a v3-style impact/exploitability computation over the v4 metrics, which
// is enough to land in the correct qualitative bucket. Flagged approximate.
func cvssV4Approx(m map[string]string) float64 {
	av := pick(m["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac := pick(m["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	at := pick(m["AT"], map[string]float64{"N": 1.0, "P": 0.9})
	pr := pick(m["PR"], map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27})
	ui := pick(m["UI"], map[string]float64{"N": 0.85, "P": 0.68, "A": 0.62})
	imp := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	// Vulnerable-system impact drives the score; subsequent-system impact adds a
	// smaller contribution.
	vc, vi, va := pick(m["VC"], imp), pick(m["VI"], imp), pick(m["VA"], imp)
	sc, si, sa := pick(m["SC"], imp), pick(m["SI"], imp), pick(m["SA"], imp)

	iss := 1 - (1-vc)*(1-vi)*(1-va)
	subISS := 1 - (1-sc)*(1-si)*(1-sa)
	impact := 6.42*iss + 1.5*subISS
	if impact <= 0 {
		return 0
	}
	expl := 8.22 * av * ac * at * pr * ui
	return roundUp(math.Min(impact+expl, 10))
}

// pick returns the weight for a metric value, or 0 if absent/unknown.
func pick(v string, table map[string]float64) float64 {
	return table[v]
}
