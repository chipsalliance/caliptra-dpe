// Licensed under the Apache-2.0 license

package verification

import (
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
)

// This file is used to test the get profile command.

// TestGetProfile tests calling GetProfile
func TestGetProfile(d client.TestDPEInstance, client client.DPEClient, t *testing.T) {
	const minTCINodes uint32 = 8

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
		if rsp.VendorID != d.GetProfileVendorID() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", d.GetProfileVendorID(), rsp.VendorID)
		}
		if rsp.VendorSku != d.GetProfileVendorSku() {
			t.Fatalf("Unexpected SKU. 0x%08x != 0x%08x", d.GetProfileVendorSku(), rsp.VendorSku)
		}
		if rsp.MaxTciNodes != d.GetMaxTciNodes() {
			t.Fatalf("Incorrect max TCI nodes. 0x%08x != 0x%08x", d.GetMaxTciNodes(), rsp.MaxTciNodes)
		}
		if rsp.MaxTciNodes < minTCINodes {
			t.Fatalf("DPE instances must be able to support at least %d TCI nodes.", minTCINodes)
		}
		if rsp.Flags != d.GetSupport().ToFlags() {
			t.Fatalf("Incorrect support flags. 0x%08x != 0x%08x", d.GetSupport().ToFlags(), rsp.Flags)
		}
	}
}
