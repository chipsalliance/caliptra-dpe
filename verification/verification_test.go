// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"flag"
	"log"
	"os"
	"reflect"
	"testing"

	"golang.org/x/exp/slices"
)

const (
	SIMULATOR string = "simulator"
	EMULATOR  string = "emulator"
)

var target_exe *string
var testTargetType string

// This will be called before running tests, and it assigns the socket path based on command line flag.
func TestMain(m *testing.M) {
	testTarget := flag.String("target", "emulator", "socket type - simulator")
	flag.Parse()
	testTargetType = *testTarget
	if testTargetType == SIMULATOR {
		target_exe = flag.String("sim", "../simulator/target/debug/simulator", "path to simulator executable")
	} else if testTargetType == EMULATOR {
		target_exe = flag.String("emu", "../server/example", "path to emulator executable")
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

// Get the test target for simulator/emulator
func GetTestTarget(support_needed []string) (TestDPEInstance, error) {

	if testTargetType == EMULATOR {
		for i := 0; i < len(support_needed); i++ {
			if !slices.Contains(emulator_supports, support_needed[i]) {
				return nil, errors.New("Requested support is not supported in the emulator")
			}
		}
		instance, err := GetEmulatorTarget(support_needed)
		if err != nil {
			return nil, err
		}
		return instance, nil
	} else if testTargetType == SIMULATOR {
		instance, err := GetSimulatorTarget(support_needed)
		if err != nil {
			return nil, err
		}
		instance.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)
		return instance, nil
	}
	return nil, errors.New("Error in creating dpe instances - supported feature is not enabled")
}

// Get the emulator target
func GetEmulatorTarget(support_needed []string) (TestDPEInstance, error) {
	// TODO : Get the supported modes from emulator and then check.
	var instance TestDPEInstance = &DpeEmulator{exe_path: *target_exe}
	if instance.HasPowerControl() {
		err := instance.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer instance.PowerOff()
	}

	client, err := NewClient384(instance)
	if err != nil {
		return nil, errors.New("Error in getting client")
	}

	rsp, err := client.GetProfile()
	if err != nil {
		return nil, errors.New("Unable to get profile")
	}

	support := Support{}

	value := reflect.ValueOf(support.ToSupport(rsp.Flags))
	for i := 0; i < len(support_needed); i++ {
		support := reflect.Indirect(value).FieldByName(support_needed[i])
		if !support.Bool() {
			return nil, errors.New("Error in creating dpe instances - supported feature is not enabled in emulator")
		}
	}
	return instance, nil
}

// Get the simulator target
func GetSimulatorTarget(support_needed []string) (TestDPEInstance, error) {

	value := reflect.ValueOf(DpeSimulator{}.supports)
	fields := reflect.Indirect(value)
	fVal := reflect.New(reflect.TypeOf(DpeSimulator{}.supports))

	for i := 0; i < len(support_needed); i++ {
		for j := 0; j < value.NumField(); j++ {
			if fields.Type().Field(j).Name == support_needed[i] {
				fVal.Elem().Field(j).SetBool(true)
			}
		}
	}
	support := fVal.Elem().Interface().(Support)
	var instance TestDPEInstance = &DpeSimulator{exe_path: *target_exe, supports: support}
	return instance, nil
}
