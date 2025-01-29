// Licensed under the Apache-2.0 license

package verification

import (
	"reflect"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
	"github.com/chipsalliance/caliptra-dpe/verification/sim"
)

// TargetExe is the simulator executable to use for this test target
var TargetExe *string

// GetSimulatorTarget gets the simulator target
func GetSimulatorTarget(supportNeeded []string, targetExe string) client.TestDPEInstance {

	value := reflect.ValueOf(client.Support{})
	fields := reflect.Indirect(value)
	fVal := reflect.New(reflect.TypeOf(client.Support{}))

	for i := 0; i < len(supportNeeded); i++ {
		for j := 0; j < value.NumField(); j++ {
			if fields.Type().Field(j).Name == supportNeeded[i] {
				fVal.Elem().Field(j).SetBool(true)
			}
		}
	}
	support := fVal.Elem().Interface().(client.Support)
	simulator := sim.NewSimulator(targetExe, support)
	return &simulator
}

// GetSimulatorTargets gets different simulator targets with different support
// vectors to run the verification tests against
func GetSimulatorTargets() []TestTarget {
	return []TestTarget{
		{
			"SupportNone",
			getTestTarget([]string{}),
			[]TestCase{GetProfileTestCase, InitializeContextTestCase},
		},
		{
			"DefaultSupport",
			getTestTarget([]string{"AutoInit", "Simulation", "X509", "Csr", "RotateContext", "Recursive", "RetainParentContext"}),
			AllTestCases,
		},
		{
			"GetProfile_Simulation",
			getTestTarget([]string{"Simulation"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_Recursive",
			getTestTarget([]string{"Recursive"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_AutoInit",
			getTestTarget([]string{"AutoInit"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_RotateContext",
			getTestTarget([]string{"RotateContext"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_X509",
			getTestTarget([]string{"X509"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_CSR",
			getTestTarget([]string{"Csr"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_InternalInfo",
			getTestTarget([]string{"InternalInfo"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_InternalDice",
			getTestTarget([]string{"InternalDice"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_RetainParentContext",
			getTestTarget([]string{"RetainParentContext"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_Combo01",
			getTestTarget([]string{"Simulation", "AutoInit", "RotateContext", "Csr", "InternalDice"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_Combo02",
			getTestTarget([]string{"Recursive", "X509", "InternalInfo"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_All",
			getTestTarget([]string{"Simulation", "Recursive", "AutoInit", "RotateContext", "X509", "Csr", "InternalInfo", "InternalDice"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"NegativeCase_UnsupportedCommandByDPE",
			getTestTarget([]string{"AutoInit"}),
			[]TestCase{UnsupportedCommand},
		},
		{
			"NegativeCase_UnsupportedFeatureByDPE",
			getTestTarget([]string{"AutoInit", "RotateContext"}),
			[]TestCase{UnsupportedCommandFlag},
		},
		{
			"DeriveContext",
			getTestTarget([]string{"AutoInit", "X509", "RetainParentContext"}),
			[]TestCase{DeriveContextTestCase},
		},
		{
			"TestDeriveContextCdiExport",
			getTestTarget([]string{"AutoInit", "CdiExport"}),
			[]TestCase{TestDeriveContextCdiExportTestCase},
		},
		{
			"DeriveContext_Simulation",
			getTestTarget([]string{"AutoInit", "Simulation", "X509", "RetainParentContext"}),
			[]TestCase{DeriveContextSimulationTestCase},
		},
		{
			"DeriveContext_PrivilegeEscalation",
			getTestTarget([]string{"AutoInit", "X509"}),
			[]TestCase{DeriveContextPrivilegeEscalationTestCase},
		},
		{
			"DeriveContext_InputFlags",
			getTestTarget([]string{"AutoInit", "Simulation", "InternalDice", "InternalInfo"}),
			[]TestCase{DeriveContextInputFlagsTestCase},
		},
		{
			"DeriveContext_MaxTCIs",
			getTestTarget([]string{"AutoInit", "Recursive", "X509"}),
			[]TestCase{DeriveContextMaxTCIsTestCase},
		},
		{
			"DeriveContext_ChangeLocality",
			getTestTarget([]string{"AutoInit", "Simulation"}),
			[]TestCase{DeriveContextLocalityTestCase},
		},
		{
			"DeriveContext_Recursive",
			getTestTarget([]string{"AutoInit", "Recursive", "X509"}),
			[]TestCase{DeriveContextRecursiveTestCase},
		},
		{
			"DeriveContext_RecursiveOnDerivedContexts",
			getTestTarget([]string{"AutoInit", "Recursive", "RetainParentContext", "X509", "RotateContext"}),
			[]TestCase{DeriveContextRecursiveOnDerivedContextsTestCase},
		},
	}
}

// Get the test target for simulator/emulator
func getTestTarget(supportNeeded []string) client.TestDPEInstance {
	instance := GetSimulatorTarget(supportNeeded, *TargetExe)
	instance.SetLocality(sim.DPESimulatorAutoInitLocality)
	return instance
}
