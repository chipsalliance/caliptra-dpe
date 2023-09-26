// Licensed under the Apache-2.0 license
package verification

import (
	"log"
	"testing"
)

type DeriveChildFlag int

const (
	InternalInputInfo DeriveChildFlag = 31
	InternalInputDice DeriveChildFlag = 30
	RetainParent      DeriveChildFlag = 29
	MakeDefault       DeriveChildFlag = 28
	ChangeLocality    DeriveChildFlag = 27
	InputAllowCA      DeriveChildFlag = 26
	InputAllowX509    DeriveChildFlag = 25
)

func TestDeriveChild(t *testing.T) {
	supportNeeded := []string{"AutoInit", "X509"}
	instance, err := GetTestTarget(supportNeeded)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestCertifyKey command due to unsupported request. Hence, skipping the command execution")
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
	r := []DeriveChildReq[SHA256Digest]{
		{
			ContextHandle:  [16]byte{0},
			InputData:      SHA256Digest{},
			Flags:          0,
			InputType:      [4]byte{},
			TargetLocality: 0,
		},
	}
	_, err = client.DeriveChild(&r[0])
	if err != nil {
		t.Fatalf("[FATAL]: Could not perform derive child command: %v", err)
	}

}
