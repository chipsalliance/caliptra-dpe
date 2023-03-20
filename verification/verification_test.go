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
		err := s.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer s.PowerOff()
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
	simulators := []DpeSimulator{
		// No extra options.
		{exe_path: *sim_exe},
		// Supports simulation.
		{exe_path: *sim_exe, supports: Support{Simulation: true}},
	}

	for _, s := range simulators {
		for _, l := range s.GetLocalities() {
			testInitContext(&s, l, t)
		}
	}
}

func testInitContext(s *DpeSimulator, locality uint32, t *testing.T) {
	if s.HasPowerControl() {
		err := s.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer s.PowerOff()
	}

	client := DpeClient{transport: s}
	// Need to set up the client completely by getting the profile.
	err, respHdr, profile := client.GetProfile(locality)
	if err != nil {
		t.Fatal(err)
	}
	if respHdr.Status != 0 {
		t.Fatal("Failed to get profile.")
	}

	// Try to create the default context if isn't done automatically.
	if !client.transport.GetSupport().AutoInit {
		err, respHdr, initCtxResp := client.Initialize(locality, NewInitCtxIsDefault())
		if err != nil {
			t.Fatal(err)
		}
		if respHdr.Status != 0 {
			t.Fatal("Failed to initialize default context.")
		}
		if initCtxResp.Handle != [16]byte{0} {
			t.Fatal("Incorrect default context handle.")
		}
		defer client.DestroyContext(locality, NewDestroyCtx(initCtxResp.Handle, false))
	}

	// Try to initialize another default context.
	err, respHdr, _ = client.Initialize(locality, NewInitCtxIsDefault())
	if err == nil {
		t.Fatal("The instance should return an error when trying to initialize another default context.")
	}
	if respHdr.Status != DPE_STATUS_ARGUMENT_NOT_SUPPORTED {
		t.Fatalf("Incorrect error type. Should return %d, but returned %d", DPE_STATUS_ARGUMENT_NOT_SUPPORTED, respHdr.Status)
	}

	// Try to initialize a context that is neither default or simulation.
	err, respHdr, _ = client.Initialize(locality, &InitCtxCmd{})
	if err == nil {
		t.Fatal("The instance should return an error when not default or simulation.")
	}
	if respHdr.Status != DPE_STATUS_INVALID_ARGUMENT {
		t.Fatalf("Incorrect error type. Should return %d, but returned %d", DPE_STATUS_INVALID_ARGUMENT, respHdr.Status)
	}

	if !client.transport.GetSupport().Simulation {
		// Try to initialize a simulation context when they aren't supported.
		err, respHdr, _ := client.Initialize(locality, NewInitCtxIsSimulation())
		if err == nil {
			t.Fatal("The instance should return an error when trying to initialize another default context.")
		}
		if respHdr.Status != DPE_STATUS_ARGUMENT_NOT_SUPPORTED {
			t.Fatalf("Incorrect error type. Should return %d, but returned %d", DPE_STATUS_ARGUMENT_NOT_SUPPORTED, respHdr.Status)
		}
	} else {
		// Try to get the correct error for overflowing the contexts. Fill up the
		// rest of the contexts (-1 for default).
		for i := uint32(0); i < profile.MaxTciNodes-1; i++ {
			err, respHdr, initCtxResp := client.Initialize(locality, NewInitCtxIsSimulation())
			if err != nil || respHdr.Status != 0 {
				t.Fatal("The instance should be able to create a simulation context.")
			}
			// Could prove difficult to prove it is a cryptographically secure random.
			if initCtxResp.Handle == [16]byte{0} {
				t.Fatal("Incorrect simulation context handle.")
			}
			defer client.DestroyContext(locality, NewDestroyCtx(initCtxResp.Handle, false))
		}

		// Now try to make one more than the max.
		err, respHdr, _ := client.Initialize(locality, NewInitCtxIsSimulation())
		if err == nil {
			t.Fatal("Failed to report an error for too many contexts.")
		}
		if respHdr.Status != DPE_STATUS_MAX_TCIS {
			t.Fatalf("Incorrect error type. Should return %d, but returned %d", DPE_STATUS_MAX_TCIS, respHdr.Status)
		}
	}
}
