// Licensed under the Apache-2.0 license

package verification

import (
	"log"
	"testing"
)

// This file is used to test the get profile command.

func TestGetProfile(t *testing.T) {

	support_needed := []string{""}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SimulationMode(t *testing.T) {

	support_needed := []string{"Simulation"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_SimulationMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_ExtendTciMode(t *testing.T) {

	support_needed := []string{"ExtendTci"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_ExtendTciMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_AutoInitMode(t *testing.T) {

	support_needed := []string{"AutoInit"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_AutoInitMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_TaggingMode(t *testing.T) {

	support_needed := []string{"Tagging"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_TaggingMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_RotateContextMode(t *testing.T) {

	support_needed := []string{"RotateContext"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_RotateContextMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_X509Mode(t *testing.T) {

	support_needed := []string{"X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_X509Mode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_CsrMode(t *testing.T) {

	support_needed := []string{"Csr"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_CsrMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_IsSymmetricMode(t *testing.T) {

	support_needed := []string{"IsSymmetric"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_IsSymmetricMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_InternalInfoMode(t *testing.T) {

	support_needed := []string{"InternalInfo"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_InternalInfoMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_InternalDiceMode(t *testing.T) {

	support_needed := []string{"InternalDice"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_InternalDiceMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_IsCAMode(t *testing.T) {

	support_needed := []string{"IsCA"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_IsCAMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportMode_01(t *testing.T) {

	support_needed := []string{"Simulation", "AutoInit", "RotateContext", "Csr", "InternalDice", "IsCA"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_SupportMode_01 command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportMode_02(t *testing.T) {

	support_needed := []string{"ExtendTci", "Tagging", "X509", "InternalInfo"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_SupportMode_02 command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_AllSupportMode(t *testing.T) {

	support_needed := []string{"Simulation", "ExtendTci", "AutoInit", "Tagging", "RotateContext", "X509", "Csr", "IsSymmetric", "InternalInfo", "InternalDice", "IsCA"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestGetProfile_AllSupportMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
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
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	client, err := NewClient(d, profile)
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	for _, locality := range d.GetSupportedLocalities() {
		d.SetLocality(locality)
		rsp, err := client.GetProfile()
		if err != nil {
			t.Fatalf("Unable to get profile: %v", err)
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
