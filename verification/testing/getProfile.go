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
			t.Errorf("Incorrect major version. 0x%08x (want) != 0x%08x (got)", d.GetProfileMajorVersion(), rsp.MajorVersion)
		}
		if rsp.MinorVersion != d.GetProfileMinorVersion() {
			t.Errorf("Incorrect minor version. 0x%08x (want) != 0x%08x (got)", d.GetProfileMinorVersion(), rsp.MinorVersion)
		}
		if rsp.VendorID != d.GetProfileVendorID() {
			t.Errorf("Incorrect vendor ID. 0x%08x (want) != 0x%08x (got)", d.GetProfileVendorID(), rsp.VendorID)
		}
		if rsp.VendorSku != d.GetProfileVendorSku() {
			t.Errorf("Incorrect SKU. 0x%08x (want) != 0x%08x (got)", d.GetProfileVendorSku(), rsp.VendorSku)
		}
		if rsp.MaxTciNodes != d.GetMaxTciNodes() {
			t.Errorf("Incorrect max TCI nodes. 0x%08x (want) != 0x%08x (got)", d.GetMaxTciNodes(), rsp.MaxTciNodes)
		}
		if rsp.MaxTciNodes < minTCINodes {
			t.Errorf("DPE instances must be able to support at least %d TCI nodes.", minTCINodes)
		}
		if rsp.Flags != d.GetSupport().ToFlags() {
			t.Errorf("Incorrect support flags. 0x%08x (want) != 0x%08x (got)", d.GetSupport().ToFlags(), rsp.Flags)
		}
	}
}
