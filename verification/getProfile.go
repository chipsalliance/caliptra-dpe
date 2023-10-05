// Licensed under the Apache-2.0 license

package verification

import (
	"testing"
)

// This file is used to test the get profile command.

func TestGetProfile(d TestDPEInstance, t *testing.T) {
	if d.HasPowerControl() {
		err := d.PowerOn()
		if err != nil {
			t.Fatal(err)
		}
		defer d.PowerOff()
	}

	const MIN_TCI_NODES uint32 = 8

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
			t.Fatalf("Unexpected SKU. 0x%08x != 0x%08x", d.GetProfileVendorSku(), rsp.VendorSku)
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
