// Licensed under the Apache-2.0 license

package verification

import (
	"testing"
)

type DpeTestFunc func(d TestDPEInstance, c DPEClient, t *testing.T)

type TestCase struct {
	Name          string
	Run           DpeTestFunc
	SupportNeeded []string
}

type TestTarget struct {
	Name      string
	D         TestDPEInstance
	TestCases []TestCase
}

var InitializeContextTestCase = TestCase{
	"InitializeContext", TestInitializeContext, []string{},
}
var InitializeContextSimulationTestCase = TestCase{
	"InitializeContextSimulation", TestInitializeSimulation, []string{"Simulation"},
}
var CertifyKeyTestCase = TestCase{
	"CertifyKey", TestCertifyKey, []string{"AutoInit", "X509", "IsCA"},
}
var CertifyKeySimulationTestCase = TestCase{
	"CertifyKeySimulation", TestCertifyKey_SimulationMode, []string{"AutoInit", "Simulation", "X509", "IsCA"},
}
var GetCertificateChainTestCase = TestCase{
	"GetCertificateChain", TestGetCertificateChain, []string{"AutoInit", "X509"},
}
var ExtendTCITestCase = TestCase{
	"ExtendTCITestCase", TestExtendTCI, []string{"AutoInit", "ExtendTci"},
}
var ExtendDerivedTciTestCase = TestCase{
	"ExtendDerivedTciTestCase", TestExtendTciOnDerivedContexts, []string{"AutoInit", "ExtendTci"},
}
var GetProfileTestCase = TestCase{
	"GetProfile", TestGetProfile, []string{},
}
var InvalidHandleTestCase = TestCase{
	"CheckInvalidHandle", TestInvalidHandle, []string{"Simulation", "RotateContext", "ExtendTci"},
}
var WrongLocalityTestCase = TestCase{
	"CheckWrongLocality", TestWrongLocality, []string{"AutoInit", "RotateContext", "ExtendTci"},
}
var UnsupportedCommand = TestCase{
	"CheckSupportForCommand", TestUnsupportedCommand, []string{"AutoInit"},
}
var UnsupportedCommandFlag = TestCase{
	"CheckSupportForCommmandFlag", TestUnsupportedCommandFlag, []string{"AutoInit", "RotateContext", "ExtendTci"},
}

var AllTestCases = []TestCase{
	CertifyKeyTestCase,
	CertifyKeySimulationTestCase,
	GetCertificateChainTestCase,
	ExtendTCITestCase,
	ExtendDerivedTciTestCase,
	GetProfileTestCase,
	InitializeContextTestCase,
	InitializeContextSimulationTestCase,
	InvalidHandleTestCase,
	WrongLocalityTestCase,
}

func RunTargetTestCases(target TestTarget, t *testing.T) {
	// This needs to be in a separate function to make sure it is powered off before running the
	// next target. This is particularly important for the simulator because it can attach to an
	// old instance if the was not closed yet.
	if target.D.HasPowerControl() {
		err := target.D.PowerOn()
		if err != nil {
			t.Fatalf("Could not power on the target: %v", err)
		}
		defer target.D.PowerOff()
	}

	profile, err := GetTransportProfile(target.D)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	c, err := NewClient(target.D, profile)
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	for _, test := range target.TestCases {
		t.Run(target.Name+"-"+test.Name, func(t *testing.T) {
			if !HasSupportNeeded(target.D, test.SupportNeeded) {
				t.Skipf("Warning: Target does not have required support, skipping test.")
			}

			test.Run(target.D, c, t)
		})
	}
}
