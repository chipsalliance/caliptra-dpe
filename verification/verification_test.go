// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"flag"
	"os"
	"reflect"
	"testing"
)

const (
	SIMULATOR string = "simulator"
	EMULATOR  string = "emulator"
)

var socket_exe *string
var testTargetType string

// This will be called before running tests, and it assigns the socket path based on command line flag.
func TestMain(m *testing.M) {
	testTarget := flag.String("target", "simulator", "socket type - emulator")
	flag.Parse()
	testTargetType = *testTarget
	if testTargetType == SIMULATOR {
		socket_exe = flag.String("sim", "../simulator/target/debug/simulator", "path to simulator executable")
	} else if testTargetType == EMULATOR {
		socket_exe = flag.String("emu", "../simulator/target/debug/emulator", "path to emulator executable")
	}

	exitVal := m.Run()
	os.Exit(exitVal)
}

// An extension to the main DPE transport interface with test hooks.
type TestDPEInstance interface {
	Transport
	// If power control is unavailable for the given device, return false from
	// HasPowerControl and return an error from PowerOn and PowerOff. For devices
	// that don't support power control but do have reset capability, return true
	// from HasPowerControl leave PowerOn empty and execute the reset in PowerOff.
	HasPowerControl() bool
	// If supported, turns on the device or starts the emulator/simulator.
	PowerOn() error
	// If supported, turns of the device, stops the emulator/simulator, or resets.
	PowerOff() error
	// The Transport implementations are not expected to be able to set the values
	// it supports, but this function is used by tests to know how to test the DPE
	// instance.
	GetSupport() *Support
	// Returns the profile the transport supports.
	GetProfile() Profile
	// Returns a slice of all the localities the instance supports.
	GetSupportedLocalities() []uint32
	// Sets the current locality.
	SetLocality(locality uint32)
	// Gets the current locality.
	GetLocality() uint32
	// Returns the Maximum number of the TCIs instance can have.
	GetMaxTciNodes() uint32
	// Returns the major version of the profile the instance implements.
	GetProfileMajorVersion() uint16
	// Returns the minor version of the profile the instance implements.
	GetProfileMinorVersion() uint16
	// Returns the Vendor ID of the profile.
	GetProfileVendorId() uint32
	// Returns the vendor's product SKU.
	GetProfileVendorSku() uint32
}

// Get the emulator target
func GetEmulatorTarget(support_needed []string, instances []TestDPEInstance) ([]TestDPEInstance, error) {

	dpeEmulator := DpeEmulator{}
	value := reflect.ValueOf(dpeEmulator.supports)
	for i := 0; i < len(support_needed); i++ {
		support := reflect.Indirect(value).FieldByName(support_needed[i])
		if !support.Bool() {
			return nil, errors.New("Error in creating dpe instances - supported feature is not enabled in emulator")
		}
	}
	instances = []TestDPEInstance{
		&DpeEmulator{exe_path: *socket_exe},
	}
	return instances, nil

}
