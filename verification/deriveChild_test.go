// Licensed under the Apache-2.0 license
package verification

import (
	"log"
	"testing"
)

func TestDeriveChild(t *testing.T) {
	//supportNeeded := []string{"AutoInit"}
	supportNeeded := []string{"Simulation", "ExtendTci", "AutoInit", "Tagging", "RotateContext", "X509", "Csr", "IsSymmetric", "InternalInfo", "InternalDice", "IsCA"}
	instance, err := GetTestTarget(supportNeeded)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("[WARNING]: Failed executing TestDeriveChild command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testDeriveChild(instance, t)
}
func testDeriveChild(d TestDPEInstance, t *testing.T) {
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

	requests := []DeriveChildReq[SHA256Digest]{{
		ContextHandle:  [16]byte{0},
		InputData:      SHA256Digest{0},
		Flags:          1 << 28,
		InputType:      0,
		TargetLocality: 0,
	}}
	for _, req := range requests {
		_, err := client.DeriveChild(&req)
		if err != nil {
			t.Fatalf("[FATAL]: Could not perform derive child command: %v", err)
		}
	}

}
