// Licensed under the Apache-2.0 license

package verification

import (
	"flag"
	"os"
	"testing"
)

// This will be called before running tests, and it assigns the socket path based on command line flag.
func TestMain(m *testing.M) {
	TargetExe = flag.String("sim", "../../target/debug/simulator", "path to simulator executable")

	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestRunAll(t *testing.T) {
	targets := GetSimulatorTargets()

	for _, target := range targets {
		RunTargetTestCases(target, t)
	}
}
