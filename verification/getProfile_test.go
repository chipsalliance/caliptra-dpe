// Licensed under the Apache-2.0 license

package verification

import (
	"log"
	"testing"
)

// This file is used to test the get profile command by using a simulator

func TestGetProfile(t *testing.T) {
	var instances []TestDPEInstance
	if *isEmulator {
		//Added dummy support for emulator. Once the emulator is implemented, will add the actual enabled feature
		instances = []TestDPEInstance{
			&DpeInstance{exe_path: *socket_exe, supports: Support{AutoInit: true}},
		}
	} else {
		instances = []TestDPEInstance{
			// No extra options.
			&DpeInstance{exe_path: *socket_exe},
			// Supports simulation.
			&DpeInstance{exe_path: *socket_exe, supports: Support{Simulation: true}},
			// Supports extended TCI.
			&DpeInstance{exe_path: *socket_exe, supports: Support{ExtendTci: true}},
			// Supports auto-init.
			&DpeInstance{exe_path: *socket_exe, supports: Support{AutoInit: true}},
			// Supports tagging.
			&DpeInstance{exe_path: *socket_exe, supports: Support{Tagging: true}},
			// Supports rotate context.
			&DpeInstance{exe_path: *socket_exe, supports: Support{RotateContext: true}},
			// Supports certify key.
			&DpeInstance{exe_path: *socket_exe, supports: Support{X509: true}},
			// Supports certify csr.
			&DpeInstance{exe_path: *socket_exe, supports: Support{Csr: true}},
			// Supports symmetric derivation.
			&DpeInstance{exe_path: *socket_exe, supports: Support{IsSymmetric: true}},
			// Supports internal info.
			&DpeInstance{exe_path: *socket_exe, supports: Support{InternalInfo: true}},
			// Supports internal DICE.
			&DpeInstance{exe_path: *socket_exe, supports: Support{InternalDice: true}},
			// Supports IsCA
			&DpeInstance{exe_path: *socket_exe, supports: Support{IsCA: true}},
			// Supports a couple combos.
			&DpeInstance{exe_path: *socket_exe, supports: Support{Simulation: true, AutoInit: true, RotateContext: true, Csr: true, InternalDice: true, IsCA: true}},
			&DpeInstance{exe_path: *socket_exe, supports: Support{ExtendTci: true, Tagging: true, X509: true, InternalInfo: true}},
			// Supports everything.
			&DpeInstance{exe_path: *socket_exe, supports: Support{Simulation: true, ExtendTci: true, AutoInit: true, Tagging: true, RotateContext: true, X509: true, Csr: true, IsSymmetric: true, InternalInfo: true, InternalDice: true, IsCA: true}},
		}
	}

	for _, instance := range instances {
		testGetProfile(instance, t)
	}
}

func testGetProfile(d TestDPEInstance, t *testing.T) {
	const MIN_TCI_NODES uint32 = 8
	if d.HasPowerControl() {
		err := d.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer d.PowerOff()
	}
	client, err := NewClient256(d)
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	for _, locality := range d.GetSupportedLocalities() {
		d.SetLocality(locality)
		rsp, err := client.GetProfile()
		if err != nil {
			t.Fatalf("Unable to get profile: %v", err)
		}
		if rsp.Profile != d.GetProfile() {
			t.Fatalf("Incorrect profile. 0x%08x != 0x%08x", d.GetProfile(), rsp.Profile)
		}
		if rsp.MajorVersion != d.GetProfileMajorVersion() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", d.GetProfileMajorVersion(), rsp.MajorVersion)
		}
		if rsp.MinorVersion != d.GetProfileMinorVersion() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", d.GetProfileMinorVersion(), rsp.MinorVersion)
		}
		if rsp.VendorId != d.GetProfileVendorId() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", d.GetProfileVendorId(), rsp.VendorId)
		}
		if rsp.VendorSku != d.GetProfileVendorSku() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", d.GetProfileVendorSku(), rsp.VendorSku)
		}
		if rsp.MaxTciNodes != d.GetMaxTciNodes() {
			t.Fatalf("Incorrect max TCI nodes. 0x%08x != 0x%08x", d.GetMaxTciNodes(), rsp.MaxTciNodes)
		}
		if rsp.MaxTciNodes < MIN_TCI_NODES {
			t.Fatalf("DPE instances must be able to support at least %d TCI nodes.", MIN_TCI_NODES)
		}
		if rsp.Flags != d.GetSupport().ToFlags() {
			t.Fatalf("Incorrect support flags. 0x%08x != 0x%08x", d.GetSupport().ToFlags(), rsp.Flags)
		}
	}
}
