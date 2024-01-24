// Licensed under the Apache-2.0 license

// Package verification provides verification tests for implementations of the DPE iRoT profile.
package verification

import (
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
)

// DpeTestFunc is the function template that a DPE test case must implement
type DpeTestFunc func(d client.TestDPEInstance, c client.DPEClient, t *testing.T)

// TestCase is metadata for a DPE test case
type TestCase struct {
	Name          string
	Run           DpeTestFunc
	SupportNeeded []string
}

// TestTarget is a client.TestDPEInstance and corresponding list of test cases to run
// against that target.
type TestTarget struct {
	Name      string
	D         client.TestDPEInstance
	TestCases []TestCase
}

// InitializeContextTestCase tests InitializeContext
var InitializeContextTestCase = TestCase{
	"InitializeContext", TestInitializeContext, []string{},
}

// InitializeContextSimulationTestCase tests InitializeContext in simulation mode
var InitializeContextSimulationTestCase = TestCase{
	"InitializeContextSimulation", TestInitializeSimulation, []string{"Simulation"},
}

// CertifyKeyTestCase tests CertifyKey
var CertifyKeyTestCase = TestCase{
	"CertifyKey", TestCertifyKey, []string{"AutoInit", "X509", "IsCA"},
}

// client.CertifyKeyCsrTestCase tests CertifyKey with type = CSR
var CertifyKeyCsrTestCase = TestCase{
	"CertifyKeyCsr", TestCertifyKeyCsr, []string{"AutoInit", "Csr", "IsCA"},
}

// CertifyKeySimulationTestCase tests CertifyKey on Simulation mode contexts
var CertifyKeySimulationTestCase = TestCase{
	"CertifyKeySimulation", TestCertifyKeySimulation, []string{"AutoInit", "Simulation", "X509", "IsCA"},
}

// GetCertificateChainTestCase tests GetCertificateChain
var GetCertificateChainTestCase = TestCase{
	"GetCertificateChain", TestGetCertificateChain, []string{"AutoInit", "X509"},
}

// GetProfileTestCase tests GetProfile
var GetProfileTestCase = TestCase{
	"GetProfile", TestGetProfile, []string{},
}

// InvalidHandleTestCase tests various commands with invalid context handles
var InvalidHandleTestCase = TestCase{
	"CheckInvalidHandle", TestInvalidHandle, []string{"Simulation", "RotateContext"},
}

// WrongLocalityTestCase tests various commands with invalid localities
var WrongLocalityTestCase = TestCase{
	"CheckWrongLocality", TestWrongLocality, []string{"AutoInit", "RotateContext"},
}

// UnsupportedCommand tests calling unsupported commands
var UnsupportedCommand = TestCase{
	"CheckSupportForCommand", TestUnsupportedCommand, []string{"AutoInit"},
}

// UnsupportedCommandFlag tests calling unsupported commands flags
var UnsupportedCommandFlag = TestCase{
	"CheckSupportForCommandFlag", TestUnsupportedCommandFlag, []string{"AutoInit", "RotateContext"},
}

// RotateContextTestCase tests RotateContext
var RotateContextTestCase = TestCase{
	"RotateContextHandle", TestRotateContextHandle, []string{"AutoInit", "RotateContext"},
}

// RotateContextSimulationTestCase tests RotateContext with Simulation contexts
var RotateContextSimulationTestCase = TestCase{
	"RotateContextHandleSimulation", TestRotateContextHandleSimulation, []string{"Simulation", "RotateContext"},
}

// SignAsymmetricTestCase tests Sign
var SignAsymmetricTestCase = TestCase{
	"Sign", TestAsymmetricSigning, []string{"AutoInit", "X509"},
}

// SignSymmetricTestCase tests Sign with is-symmetric = true
var SignSymmetricTestCase = TestCase{
	"SignSymmetric", TestSymmetricSigning, []string{"AutoInit", "IsSymmetric"},
}

// SignSimulationTestCase tests Sign with Simulation contexts
var SignSimulationTestCase = TestCase{
	"SignSimulation", TestSignSimulation, []string{"Simulation"},
}

// TpmPolicySigningTestCase tests using DPE to satisfy TPM PolicySigned
var TpmPolicySigningTestCase = TestCase{
	"TPMPolicySigning", TestTpmPolicySigning, []string{"AutoInit", "X509"},
}

// AllTestCases contains all DPE test cases
var AllTestCases = []TestCase{
	CertifyKeyTestCase,
	CertifyKeyCsrTestCase,
	CertifyKeySimulationTestCase,
	GetCertificateChainTestCase,
	TpmPolicySigningTestCase,
	RotateContextTestCase,
	RotateContextSimulationTestCase,
	SignAsymmetricTestCase,
	SignSymmetricTestCase,
	SignSimulationTestCase,
	GetProfileTestCase,
	InitializeContextTestCase,
	InitializeContextSimulationTestCase,
	InvalidHandleTestCase,
	WrongLocalityTestCase,
}

// RunTargetTestCases runs all test cases for target
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

	profile, err := client.GetTransportProfile(target.D)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	c, err := client.NewClient(target.D, profile)
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	for _, test := range target.TestCases {
		t.Run(target.Name+"-"+test.Name, func(t *testing.T) {
			if !client.HasSupportNeeded(target.D, test.SupportNeeded) {
				t.Skipf("Warning: Target does not have required support, skipping test.")
			}

			test.Run(target.D, c, t)
		})
	}
}
