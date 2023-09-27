// Licensed under the Apache-2.0 license
package verification

import (
	"log"
	"testing"
)

func TestDeriveChildLimit(t *testing.T) {
	//supportNeeded := []string{"AutoInit"}
	supportNeeded := []string{"AutoInit"}
	instance, err := GetTestTarget(supportNeeded)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("[WARNING]: Failed executing TestDeriveChild command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testDeriveChildLimit(instance, t)
}

// Test the limits on number of DeriveChild calls
func testDeriveChildLimit(d TestDPEInstance, t *testing.T) {
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

	tciNodeCount := uint32(1)
	for {
		req := DeriveChildReq[SHA256Digest]{
			ContextHandle:  [16]byte{0},
			InputData:      SHA256Digest{0},
			Flags:          1 << MakeDefault,
			InputType:      0,
			TargetLocality: 0,
		}
		_, err := client.DeriveChild(&req)

		if tciNodeCount >= d.GetMaxTciNodes() {
			if err != nil {
				if err == StatusMaxTCIs {
					t.Logf("[LOG]: A proper error indicates that number of TCI nodes exceeds the allowed maximum TCI nodes : %s", err.Error())
				} else {
					t.Skipf("[WARNING]: Unexpected error message indicates that number of TCI nodes exceeds the allowed maximum TCI nodes: %v ", err)
				}
			} else {
				t.Errorf("[ERROR]: No error indicates that the number of TCI nodes exceeds the allowed maximum TCI nodes : %s", err.Error())
			}
			break
		} else if err != nil {
			t.Fatalf("[FATAL]: Could not perform derive child command: %v", err)
		}
		tciNodeCount++
	}
}

func TestDeriveChildPrivileges(t *testing.T) {
	//supportNeeded := []string{"AutoInit"}
	supportNeeded := []string{"AutoInit"}
	instance, err := GetTestTarget(supportNeeded)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("[WARNING]: Failed executing TestDeriveChild command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testDeriveChildPrivileges(instance, t)
}

// Test that DeriveChild privileges (like ALLOW_CA) are correctly bounded
// and that a DPE context cannot escalate its privileges.
func testDeriveChildPrivileges(d TestDPEInstance, t *testing.T) {
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

	req := DeriveChildReq[SHA256Digest]{
		ContextHandle:  [16]byte{0},
		InputData:      SHA256Digest{0},
		Flags:          1<<MakeDefault | 1<<InputAllowX509,
		InputType:      0,
		TargetLocality: 0,
	}
	_, err = client.DeriveChild(&req)
	if err != nil {
		if err == StatusArgumentNotSupported {
			t.Logf("[LOG]: Correct error code reported for unsupported privilege: %v", err)
		} else {
			t.Errorf("[Error]: Incorrect error code reported for unsupported privilege, want %v but got ", err)
		}
	}

	req = DeriveChildReq[SHA256Digest]{
		ContextHandle:  [16]byte{0},
		InputData:      SHA256Digest{0},
		Flags:          1<<MakeDefault | 1<<InputAllowCA,
		InputType:      0,
		TargetLocality: 0,
	}
	_, err = client.DeriveChild(&req)
	if err != nil {
		if err == StatusArgumentNotSupported {
			t.Logf("[LOG]: Correct error code reported for unsupported privilege: %v", err)
		} else {
			t.Errorf("[Error]: Incorrect error code reported for unsupported privilege, want %v but got ", err)
		}
	}
}
