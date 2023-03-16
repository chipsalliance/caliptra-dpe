package verification

import (
	"flag"
	"log"
	"testing"
)

var sim_exe = flag.String("sim", "../simulator/target/debug/simulator", "path to simulator executable")

func TestGetProfile(t *testing.T) {
	simulators := []DpeSimulator{
		// No extra options.
		{exe_path: *sim_exe},
		// Supports simulation.
		{exe_path: *sim_exe, supports: Support{Simulation: true}},
		// Supports extended TCI.
		{exe_path: *sim_exe, supports: Support{ExtendTci: true}},
		// Supports auto-init.
		{exe_path: *sim_exe, supports: Support{AutoInit: true}},
		// Supports tagging.
		{exe_path: *sim_exe, supports: Support{Tagging: true}},
		// Supports rotate context.
		{exe_path: *sim_exe, supports: Support{RotateContext: true}},
		// Supports a couple combos.
		{exe_path: *sim_exe, supports: Support{Simulation: true, AutoInit: true, RotateContext: true}},
		{exe_path: *sim_exe, supports: Support{ExtendTci: true, Tagging: true}},
		// Supports everything.
		{exe_path: *sim_exe, supports: Support{Simulation: true, ExtendTci: true, AutoInit: true, Tagging: true, RotateContext: true}},
	}

	for _, s := range simulators {
		testGetProfile(&s, t)
	}
}

func testGetProfile(s *DpeSimulator, t *testing.T) {
	const MIN_TCI_NODES uint32 = 8
	if s.HasPowerControl() {
		defer s.PowerOff()
		err := s.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
	}
	client := DpeClient{transport: s}

	for _, locality := range s.GetLocalities() {
		err, respHdr, profile := client.GetProfile(locality)
		if err != nil {
			t.Fatal(err)
		}
		if respHdr.Status != 0 {
			t.Fatal("Unable to get profile.")
		}
		if respHdr.Profile != s.GetProfile() {
			t.Fatalf("Incorrect profile. 0x%08x != 0x%08x", s.GetProfile(), respHdr.Profile)
		}
		if profile.Version != s.GetProfileVersion() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", s.GetProfileVersion(), profile.Version)
		}
		if profile.MaxTciNodes != s.GetMaxTciNodes() {
			t.Fatalf("Incorrect max TCI nodes. 0x%08x != 0x%08x", s.GetMaxTciNodes(), profile.MaxTciNodes)
		}
		if profile.MaxTciNodes < MIN_TCI_NODES {
			t.Fatalf("DPE instances must be able to support at least %d TCI nodes.", MIN_TCI_NODES)
		}
		if profile.Flags != s.supports.ToFlags() {
			t.Fatalf("Incorrect support flags. 0x%08x != 0x%08x", s.supports.ToFlags(), profile.Flags)
		}
	}
}

func TestInitializeContext(t *testing.T) {
	simulator := DpeSimulator{exe_path: *sim_exe}
	defer simulator.PowerOff()
	err := simulator.PowerOn()
	if err != nil {
		log.Fatal(err)
	}

	client := DpeClient{transport: &simulator}
	err, respHdr, _ := client.GetProfile(DPE_SIMULATOR_AUTO_INIT_LOCALITY)
	if err != nil {
		t.Fatal(err)
	}
	if respHdr.Status != DPE_STATUS_SUCCESS {
		t.Fatal("Unable to get profile.")
	}

	err, respHdr, _ = client.Initialize(DPE_SIMULATOR_AUTO_INIT_LOCALITY, NewInitCtxIsDefault())
	if err != nil {
		t.Fatal(err)
	}
	if respHdr.Status != 0 {
		t.Fatal("Failed to initialize default context.")
	}
}
