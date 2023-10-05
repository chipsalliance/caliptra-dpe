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
	TestCase{
		"InitializeContextSimulation", TestInitializeSimulation, []string{"Simulation"},
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
}
