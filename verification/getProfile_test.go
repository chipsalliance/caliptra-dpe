// Licensed under the Apache-2.0 license

package verification

import (
	"log"
	"testing"
)

// This file is used to test the get profile command by using a simulator/emulator

func TestGetProfile_SupportSetOne(t *testing.T) {

	support_needed := []string{""}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetOne command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetTwo(t *testing.T) {

	support_needed := []string{"Simulation"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetTwo command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetThree(t *testing.T) {

	support_needed := []string{"ExtendTci"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetThree command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetFour(t *testing.T) {

	support_needed := []string{"AutoInit"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetFour command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetFive(t *testing.T) {

	support_needed := []string{"Tagging"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetFive command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetSix(t *testing.T) {

	support_needed := []string{"RotateContext"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetSix command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetSeven(t *testing.T) {

	support_needed := []string{"X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetSeven command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetEight(t *testing.T) {

	support_needed := []string{"Csr"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetEight command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetNine(t *testing.T) {

	support_needed := []string{"IsSymmetric"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetNine command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetTen(t *testing.T) {

	support_needed := []string{"InternalInfo"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetTen command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetEleven(t *testing.T) {

	support_needed := []string{"InternalDice"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetEleven command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetTwelve(t *testing.T) {

	support_needed := []string{"IsCA"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetTwelve command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetThirteen(t *testing.T) {

	support_needed := []string{"Simulation", "AutoInit", "RotateContext", "Csr", "InternalDice", "IsCA"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetThirteen command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetFourteen(t *testing.T) {

	support_needed := []string{"ExtendTci", "Tagging", "X509", "InternalInfo"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetFourteen command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	testGetProfile(instance, t)
}

func TestGetProfile_SupportSetFifteen(t *testing.T) {

	support_needed := []string{"Simulation", "ExtendTci", "AutoInit", "Tagging", "RotateContext", "X509", "Csr", "IsSymmetric", "InternalInfo", "InternalDice", "IsCA"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestGetProfile_SupportSetFifteen command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
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
