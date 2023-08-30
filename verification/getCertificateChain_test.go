// Licensed under the Apache-2.0 license

package verification

import (
	"fmt"
	"log"
	"testing"
)

// This file is used to test the Get Certificate Chain command by using a simulator/emulator

func TestGetCertificateChain(t *testing.T) {
	support_needed := []string{"AutoInit", "X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestCertifyKey command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testGetCertificateChain(instance, t)
}

func TestGetCertificateChain_SimulationMode(t *testing.T) {

	support_needed := []string{"AutoInit", "Simulation", "X509"}
	instance, err := GetTestTarget(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in the emulator" {
			t.Skipf("Warning: Failed executing TestCertifyKey_SimulationMode command due to unsupported request. Hence, skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}
	testGetCertificateChain(instance, t)
}

func testGetCertificateChain(d TestDPEInstance, t *testing.T) {
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

	getCertificateChainReq := GetCertificateChainReq{
		Offset: 0,
		Size:   2048,
	}

	getCertificateChainResp, err := client.GetCertificateChain(&getCertificateChainReq)
	if err != nil {
		t.Fatalf("Could not get Certificate Chain: %v", err)
	}

	fmt.Println(getCertificateChainResp)
	//checkCertificateStructure(t, getCertificateChainResp.CertificateChain[0])

	// TODO: When DeriveChild is implemented, call it here to add more TCIs and call CertifyKey again. ?????
}
