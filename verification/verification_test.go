// Licensed under the Apache-2.0 license

package verification

import (
	"flag"
	"os"
	"testing"
)

var target_exe *string
var testTargetType string

// This will be called before running tests, and it assigns the socket path based on command line flag.
func TestMain(m *testing.M) {
	target_exe = flag.String("sim", "../simulator/target/debug/simulator", "path to simulator executable")

	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestRunAll(t *testing.T) {
	for _, test := range TestCases {
		t.Run(test.Name, func(t *testing.T) {
			d, err := GetTestTarget(test.SupportNeeded)
			if err != nil {
				t.Errorf("Unable to get test target: %v", err)
			}

			if !HasSupportNeeded(d, test.SupportNeeded) {
				t.Skipf("Warning: Target does not have required support, skipping test.")
			}

			test.Run(d, t)
		})
	}
}

// Get the test target for simulator/emulator
func GetTestTarget(supportNeeded []string) (TestDPEInstance, error) {
	instance, err := GetSimulatorTarget(supportNeeded, *target_exe)
	if err != nil {
		return nil, err
	}
	instance.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)
	return instance, nil
}
