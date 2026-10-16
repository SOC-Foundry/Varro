package server

import (
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestUndeclaredTarget(t *testing.T) {
	ips := newIPIndex()
	ips.set("10.0.0.10", "pg")
	ips.set("10.0.0.12", "pg2")
	ips.set("10.0.0.19", "mon")
	deps := []model.DeclaredDep{
		{Kind: model.DepKindDatabase, TargetHost: "10.0.0.10"},               // → pg
		{Kind: model.DepKindDatabase, TargetHost: "10.0.0.12"},               // → pg2
		{Kind: model.DepKindSystemd, From: "a.service", Target: "b.service"}, // local, no host
		{Kind: model.DepKindService, TargetHost: "8.8.8.8"},                  // external, unresolvable
	}
	// pg and pg2 are declared → not drift
	if undeclaredTarget(deps, ips, "pg") {
		t.Error("pg is a declared target, should not be flagged")
	}
	if undeclaredTarget(deps, ips, "pg2") {
		t.Error("pg2 is a declared target, should not be flagged")
	}
	// mon is NOT declared but there ARE resolvable declared deps → drift
	if !undeclaredTarget(deps, ips, "mon") {
		t.Error("mon is undeclared and should be flagged as drift")
	}
	// no resolvable declared deps → can't judge → never flag
	ips2 := newIPIndex()
	only := []model.DeclaredDep{{Kind: model.DepKindService, TargetHost: "8.8.8.8"}} // unresolvable
	if undeclaredTarget(only, ips2, "anything") {
		t.Error("with no resolvable declared deps, nothing should be flagged")
	}
	if undeclaredTarget(nil, ips2, "anything") {
		t.Error("with no declared deps, nothing should be flagged")
	}
}

func TestDriftShouldAlert(t *testing.T) {
	s := &Server{}
	key := "depdown|a|b"
	if !s.driftShouldAlert(key, time.Hour) {
		t.Fatal("first alert should fire")
	}
	if s.driftShouldAlert(key, time.Hour) {
		t.Error("second alert within the window should be suppressed")
	}
	if !s.driftShouldAlert("depdown|a|c", time.Hour) {
		t.Error("a different key should fire independently")
	}
	// a zero window always fires (re-alert)
	if !s.driftShouldAlert(key, 0) {
		t.Error("with a zero window the alert should fire again")
	}
}
