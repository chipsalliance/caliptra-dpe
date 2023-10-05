// Licensed under the Apache-2.0 license

package verification

import (
	"testing"
)

type DpeTestFunc func(d TestDPEInstance, t *testing.T)

type TestCase struct {
	Name          string
	Run           DpeTestFunc
	SupportNeeded []string
}

var TestCases = []TestCase{
	// InitializeContext
	TestCase{
		"InitializeContext", TestInitializeContext, []string{},
	},
	// CertifyKey
	TestCase{
		"CertifyKey", TestCertifyKey, []string{"AutoInit", "X509", "IsCA"},
	},
	TestCase{
		"CertifyKeySimulation", TestCertifyKey_SimulationMode, []string{"AutoInit", "Simulation", "X509", "IsCA"},
	},
	// GetCertificateChain
	TestCase{
		"GetCertificateChain", TestGetCertificateChain, []string{"AutoInit", "X509"},
	},
	// TagTCI
	TestCase{
		"TagTCI", TestTagTCI, []string{"AutoInit", "Tagging"},
	},
	// GetProfile
	TestCase{
		"GetProfile", TestGetProfile, []string{},
	},
	TestCase{
		"GetProfile_Simulation", TestGetProfile, []string{"Simulation"},
	},
	TestCase{
		"GetProfile_ExtendTCI", TestGetProfile, []string{"ExtendTci"},
	},
	TestCase{
		"GetProfile_AutoInit", TestGetProfile, []string{"AutoInit"},
	},
	TestCase{
		"GetProfile_Tagging", TestGetProfile, []string{"Tagging"},
	},
	TestCase{
		"GetProfile_RotateContext", TestGetProfile, []string{"RotateContext"},
	},
	TestCase{
		"GetProfile_X509", TestGetProfile, []string{"X509"},
	},
	TestCase{
		"GetProfile_CSR", TestGetProfile, []string{"Csr"},
	},
	TestCase{
		"GetProfile_Symmetric", TestGetProfile, []string{"IsSymmetric"},
	},
	TestCase{
		"GetProfile_InternalInfo", TestGetProfile, []string{"InternalInfo"},
	},
	TestCase{
		"GetProfile_InternalDice", TestGetProfile, []string{"InternalDice"},
	},
	TestCase{
		"GetProfile_IsCA", TestGetProfile, []string{"IsCA"},
	},
	TestCase{
		"GetProfile_Combo01", TestGetProfile, []string{"Simulation", "AutoInit", "RotateContext", "Csr", "InternalDice", "IsCA"},
	},
	TestCase{
		"GetProfile_Combo02", TestGetProfile, []string{"ExtendTci", "Tagging", "X509", "InternalInfo"},
	},
	TestCase{
		"GetProfile_All", TestGetProfile, []string{"Simulation", "ExtendTci", "AutoInit", "Tagging", "RotateContext", "X509", "Csr", "IsSymmetric", "InternalInfo", "InternalDice", "IsCA"},
	},
}
