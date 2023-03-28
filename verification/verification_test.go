package verification

import (
	"errors"
	"flag"
	"log"
	"testing"
)

var sim_exe = flag.String("sim", "../simulator/target/debug/simulator", "path to simulator executable")

// An extension to the main DPE transport interface with test hooks.
type TestDPEInstance interface {
	Transport
	// If power control is unavailable for the given device, return false from
	// HasPowerControl and return an error from PowerOn and PowerOff. For devices
	// that don't support power control but do have reset capability, return true
	// from HasPowerControl leave PowerOn empty and execute the reset in PowerOff.
	HasPowerControl() bool
	// If supported, turns on the device or starts the emulator/simulator.
	PowerOn() error
	// If supported, turns of the device, stops the emulator/simulator, or resets.
	PowerOff() error
	// The Transport implementations are not expected to be able to set the values
	// it supports, but this function is used by tests to know how to test the DPE
	// instance.
	GetSupport() *Support
	// Returns the profile the transport supports.
	GetProfile() uint32
	// Returns a slice of all the localities the instance supports.
	GetSupportedLocalities() []uint32
	// Sets the current locality.
	SetLocality(locality uint32) error
	// Gets the current locality.
	GetLocality() uint32
	// Returns the Maximum number of the TCIs instance can have.
	GetMaxTciNodes() uint32
	// Returns the version of the profile the instance implements.
	GetProfileVersion() uint32
}

func TestGetProfile(t *testing.T) {
	simulators := []TestDPEInstance{
		// No extra options.
		&DpeSimulator{exe_path: *sim_exe},
		// Supports simulation.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Simulation: true}},
		// Supports extended TCI.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{ExtendTci: true}},
		// Supports auto-init.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{AutoInit: true}},
		// Supports tagging.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Tagging: true}},
		// Supports rotate context.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{RotateContext: true}},
		// Supports a couple combos.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Simulation: true, AutoInit: true, RotateContext: true}},
		&DpeSimulator{exe_path: *sim_exe, supports: Support{ExtendTci: true, Tagging: true}},
		// Supports everything.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Simulation: true, ExtendTci: true, AutoInit: true, Tagging: true, RotateContext: true}},
	}

	for _, s := range simulators {
		testGetProfile(s, t)
	}
}

func testGetProfile(s TestDPEInstance, t *testing.T) {
	const MIN_TCI_NODES uint32 = 8
	if s.HasPowerControl() {
		err := s.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer s.PowerOff()
	}
	client := DpeClient{transport: s}

	for _, locality := range s.GetSupportedLocalities() {
		if err := s.SetLocality(locality); err != nil {
			t.Fatalf("Unable to set locality: %v", err)
		}
		rsp, err := client.GetProfile()
		if err != nil {
			t.Fatalf("Unable to get profile: %v", err)
		}
		if rsp.Profile != s.GetProfile() {
			t.Fatalf("Incorrect profile. 0x%08x != 0x%08x", s.GetProfile(), rsp.Profile)
		}
		if rsp.Version != s.GetProfileVersion() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", s.GetProfileVersion(), rsp.Version)
		}
		if rsp.MaxTciNodes != s.GetMaxTciNodes() {
			t.Fatalf("Incorrect max TCI nodes. 0x%08x != 0x%08x", s.GetMaxTciNodes(), rsp.MaxTciNodes)
		}
		if rsp.MaxTciNodes < MIN_TCI_NODES {
			t.Fatalf("DPE instances must be able to support at least %d TCI nodes.", MIN_TCI_NODES)
		}
		if rsp.Flags != s.GetSupport().ToFlags() {
			t.Fatalf("Incorrect support flags. 0x%08x != 0x%08x", s.GetSupport().ToFlags(), rsp.Flags)
		}
	}
}

func TestInitializeContext(t *testing.T) {
	simulators := []TestDPEInstance{
		// No extra options.
		&DpeSimulator{exe_path: *sim_exe},
		// Supports simulation.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Simulation: true}},
	}

	for _, s := range simulators {
		for _, l := range s.GetSupportedLocalities() {
			if err := s.SetLocality(l); err != nil {
				t.Fatalf("Unable to set locality: %v", err)
			}
			testInitContext(s, t)
		}
	}
}

func testInitContext(s TestDPEInstance, t *testing.T) {
	if s.HasPowerControl() {
		err := s.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer s.PowerOff()
	}

	client := DpeClient{transport: s}
	// Need to set up the client completely by getting the getProfileRsp.
	getProfileRsp, err := client.GetProfile()
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}

	// Try to create the default context if isn't done automatically.
	if !s.GetSupport().AutoInit {
		initCtxResp, err := client.Initialize(NewInitCtxIsDefault())
		if err != nil {
			t.Fatalf("Failed to initialize default context: %v", err)
		}
		if initCtxResp.Handle != [16]byte{0} {
			t.Fatal("Incorrect default context handle.")
		}
		defer client.DestroyContext(NewDestroyCtx(initCtxResp.Handle, false))
	}

	// Try to initialize another default context.
	_, err = client.Initialize(NewInitCtxIsDefault())
	if err == nil {
		t.Fatal("The instance should return an error when trying to initialize another default context.")
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Try to initialize a context that is neither default or simulation.
	_, err = client.Initialize(&InitCtxCmd{})
	if err == nil {
		t.Fatal("The instance should return an error when not default or simulation.")
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}

	if !s.GetSupport().Simulation {
		// Try to initialize a simulation context when they aren't supported.
		_, err = client.Initialize(NewInitCtxIsSimulation())
		if err == nil {
			t.Fatal("The instance should return an error when trying to initialize another default context.")
		} else if !errors.Is(err, StatusArgumentNotSupported) {
			t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusArgumentNotSupported, err)
		}
	} else {
		// Try to get the correct error for overflowing the contexts. Fill up the
		// rest of the contexts (-1 for default).
		for i := uint32(0); i < getProfileRsp.MaxTciNodes-1; i++ {
			initCtxResp, err := client.Initialize(NewInitCtxIsSimulation())
			if err != nil {
				t.Fatal("The instance should be able to create a simulation context.")
			}
			// Could prove difficult to prove it is a cryptographically secure random.
			if initCtxResp.Handle == [16]byte{0} {
				t.Fatal("Incorrect simulation context handle.")
			}
			defer client.DestroyContext(NewDestroyCtx(initCtxResp.Handle, false))
		}

		// Now try to make one more than the max.
		_, err = client.Initialize(NewInitCtxIsSimulation())
		if err == nil {
			t.Fatal("Failed to report an error for too many contexts.")
		} else if !errors.Is(err, StatusMaxTCIs) {
			t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusMaxTCIs, err)
		}
	}
}
