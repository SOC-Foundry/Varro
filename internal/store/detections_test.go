package store

import (
	"context"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestDetectionRulesCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	r, err := s.CreateDetectionRule(ctx, model.DetectionRule{
		OrgID: "org1", Name: "nc shell", Enabled: true, Severity: "HIGH", MITRE: "T1059",
		Stream: model.DetStreamProcess, Source: "custom",
		Conditions: []model.DetCond{{Field: "image", Op: "endswith", Values: []string{"/nc", "/ncat"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == "" {
		t.Fatal("no id")
	}
	// Scope isolation.
	if _, err := s.CreateDetectionRule(ctx, model.DetectionRule{OrgID: "org2", Name: "other", Severity: "LOW", Stream: model.DetStreamProcess}); err != nil {
		t.Fatal(err)
	}
	got, err := s.DetectionRules(ctx, "org1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "nc shell" {
		t.Fatalf("org1 rules = %+v", got)
	}
	if len(got[0].Conditions) != 1 || len(got[0].Conditions[0].Values) != 2 {
		t.Fatalf("conditions round-trip wrong: %+v", got[0].Conditions)
	}

	// Toggle + delete.
	if ok, err := s.SetDetectionRuleEnabled(ctx, "org1", r.ID, false); err != nil || !ok {
		t.Fatalf("toggle: %v %v", ok, err)
	}
	if got, _ := s.DetectionRules(ctx, "org1"); got[0].Enabled {
		t.Error("rule should be disabled")
	}
	if ok, err := s.DeleteDetectionRule(ctx, "org2", r.ID); err != nil || ok {
		t.Error("cross-org delete should fail")
	}
	if ok, err := s.DeleteDetectionRule(ctx, "org1", r.ID); err != nil || !ok {
		t.Errorf("delete: %v %v", ok, err)
	}
}

func TestDetectionSettings(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.SetDetectionSetting(ctx, "org1", model.DetectionSetting{RuleName: "crypto_miner", Enabled: false, Severity: "CRITICAL"}); err != nil {
		t.Fatal(err)
	}
	// Upsert replaces.
	if err := s.SetDetectionSetting(ctx, "org1", model.DetectionSetting{RuleName: "crypto_miner", Enabled: true, Severity: ""}); err != nil {
		t.Fatal(err)
	}
	m, err := s.DetectionSettings(ctx, "org1")
	if err != nil {
		t.Fatal(err)
	}
	st, ok := m["crypto_miner"]
	if !ok || !st.Enabled || st.Severity != "" {
		t.Fatalf("setting = %+v (ok=%v), want enabled + no severity override", st, ok)
	}
	if other, _ := s.DetectionSettings(ctx, "org2"); len(other) != 0 {
		t.Error("org2 should have no settings")
	}
}
