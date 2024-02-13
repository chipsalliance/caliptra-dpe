// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"time"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
)

// Constants for configuring expected values from the DPE simulator
const (
	simulatorSocketPath = "/tmp/dpe-sim.socket"

	DPESimulatorAutoInitLocality    uint32 = 0
	DPESimulatorOtherLocality       uint32 = 0x4f544852
	DPESimulatorMaxTCINodes         uint32 = 24
	DPESimulatorMajorProfileVersion uint16 = client.CurrentProfileMajorVersion
	DPESimulatorMinorProfileVersion uint16 = client.CurrentProfileMinorVersion
	DPESimulatorVendorID            uint32 = 0
	DPESimulatorVendorSKU           uint32 = 0
)

// TargetExe is the simulator executable to use for this test target
var TargetExe *string

// DpeSimulator is a handle to a DPE simulator instance
type DpeSimulator struct {
	exePath         string
	cmd             *exec.Cmd
	supports        client.Support
	currentLocality uint32
	isInitialized   bool
	client.Transport
}

// HasPowerControl returns whether the simulator can be started and stopped.
func (s *DpeSimulator) HasPowerControl() bool {
	return true
}

// PowerOn starts the simulator.
func (s *DpeSimulator) PowerOn() error {
	args := []string{}
	if s.supports.Simulation {
		args = append(args, "--supports-simulation")
	}
	if s.supports.Recursive {
		args = append(args, "--supports-recursive")
	}
	if s.supports.AutoInit {
		args = append(args, "--supports-auto-init")
	}
	if s.supports.RotateContext {
		args = append(args, "--supports-rotate-context")
	}
	if s.supports.X509 {
		args = append(args, "--supports-x509")
	}
	if s.supports.Csr {
		args = append(args, "--supports-csr")
	}
	if s.supports.IsCA {
		args = append(args, "--supports-is-ca")
	}
	if s.supports.IsSymmetric {
		args = append(args, "--supports-is-symmetric")
	}
	if s.supports.InternalInfo {
		args = append(args, "--supports-internal-info")
	}
	if s.supports.InternalDice {
		args = append(args, "--supports-internal-dice")
	}
	if s.supports.RetainParentContext {
		args = append(args, "--supports-retain-parent-context")
	}

	s.cmd = exec.Command(s.exePath, args...)
	s.cmd.Stdout = os.Stdout
	err := s.cmd.Start()
	if err != nil {
		return err
	}
	if !s.waitForPower( /*on=*/ true) {
		return errors.New("the simulator never started")
	}
	return nil
}

// PowerOff kills the simulator in a way that it can cleanup before closing.
func (s *DpeSimulator) PowerOff() error {
	if s.cmd != nil {
		err := s.cmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			return err
		}
		if !s.waitForPower( /*on=*/ false) {
			return errors.New("the simulator never stopped")
		}
	}
	return nil
}

// Wait for the simulator to come alive. Timeout at 15 seconds.
func (s *DpeSimulator) waitForPower(on bool) bool {
	timeoutSeconds := 15
	checksPerSec := 50

	for i := 0; i < checksPerSec*timeoutSeconds; i++ {
		// Check if the socket file has been created.
		if fileExists(simulatorSocketPath) == on {
			return true
		}
		time.Sleep(time.Duration(1000/checksPerSec) * time.Millisecond)
	}
	return false
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// SendCmd sends a DPE command to the simulator
func (s *DpeSimulator) SendCmd(buf []byte) ([]byte, error) {
	// Connect to DPE instance.
	conn, err := net.Dial("unix", simulatorSocketPath)
	if err != nil {
		return nil, err
	}

	// Prepend the command with the locality.
	prepended := bytes.NewBuffer(make([]byte, 0, 4+len(buf)))
	if err := binary.Write(prepended, binary.LittleEndian, s.currentLocality); err != nil {
		return nil, err
	}
	if _, err := prepended.Write(buf); err != nil {
		return nil, err
	}

	// Send the prepended command.
	numSent, err := conn.Write(prepended.Bytes())
	if err != nil {
		return nil, err
	}
	if numSent != len(prepended.Bytes()) {
		return nil, errors.New("didn't send the whole command")
	}

	// Get the response.
	return io.ReadAll(conn)
}

// GetSupport gets supported DPE features from the simulator
func (s *DpeSimulator) GetSupport() *client.Support {
	return &s.supports
}

// GetIsInitialized gets whether DPE is initialized
func (s *DpeSimulator) GetIsInitialized() bool {
	return s.supports.AutoInit || s.isInitialized
}

// SetIsInitialized sets whether DPE is initialized
func (s *DpeSimulator) SetIsInitialized(isInitialized bool) {
	s.isInitialized = isInitialized
}

// GetSupportedLocalities gets the list of localities the simulator supports
func (s *DpeSimulator) GetSupportedLocalities() []uint32 {
	return []uint32{DPESimulatorAutoInitLocality, DPESimulatorOtherLocality}
}

// HasLocalityControl returns whether the simulator can artificially set the
// locality of the caller. The simulator target can always control the locality.
func (s *DpeSimulator) HasLocalityControl() bool {
	return true
}

// SetLocality sets the locality of this caller
func (s *DpeSimulator) SetLocality(locality uint32) {
	s.currentLocality = locality
}

// GetLocality gets the locality of the current caller
func (s *DpeSimulator) GetLocality() uint32 {
	return s.currentLocality
}

// GetMaxTciNodes gets the max number of TCI nodes the DPE supports
func (s *DpeSimulator) GetMaxTciNodes() uint32 {
	return DPESimulatorMaxTCINodes
}

// GetProfileMajorVersion gets the major profile version supported by this DPE
func (s *DpeSimulator) GetProfileMajorVersion() uint16 {
	return DPESimulatorMajorProfileVersion
}

// GetProfileMinorVersion gets the minor profile version supported by this DPE
func (s *DpeSimulator) GetProfileMinorVersion() uint16 {
	return DPESimulatorMinorProfileVersion
}

// GetProfileVendorID gets the vendor ID of this DPE
func (s *DpeSimulator) GetProfileVendorID() uint32 {
	return DPESimulatorVendorID
}

// GetProfileVendorSku gets the vendor SKU of this DPE
func (s *DpeSimulator) GetProfileVendorSku() uint32 {
	return DPESimulatorVendorSKU
}

// GetSimulatorTarget gets the simulator target
func GetSimulatorTarget(supportNeeded []string, targetExe string) client.TestDPEInstance {

	value := reflect.ValueOf(DpeSimulator{}.supports)
	fields := reflect.Indirect(value)
	fVal := reflect.New(reflect.TypeOf(DpeSimulator{}.supports))

	for i := 0; i < len(supportNeeded); i++ {
		for j := 0; j < value.NumField(); j++ {
			if fields.Type().Field(j).Name == supportNeeded[i] {
				fVal.Elem().Field(j).SetBool(true)
			}
		}
	}
	support := fVal.Elem().Interface().(client.Support)
	var instance client.TestDPEInstance = &DpeSimulator{exePath: targetExe, supports: support}
	return instance
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
			getTestTarget([]string{"AutoInit", "Simulation", "X509", "Csr", "IsCA", "RotateContext", "Recursive", "IsSymmetric", "RetainParentContext"}),
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
			"GetProfile_Symmetric",
			getTestTarget([]string{"IsSymmetric"}),
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
			"GetProfile_IsCA",
			getTestTarget([]string{"IsCA"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_RetainParentContext",
			getTestTarget([]string{"RetainParentContext"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_Combo01",
			getTestTarget([]string{"Simulation", "AutoInit", "RotateContext", "Csr", "InternalDice", "IsCA"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_Combo02",
			getTestTarget([]string{"Recursive", "X509", "InternalInfo"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_All",
			getTestTarget([]string{"Simulation", "Recursive", "AutoInit", "RotateContext", "X509", "Csr", "IsSymmetric", "InternalInfo", "InternalDice", "IsCA"}),
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
			getTestTarget([]string{"AutoInit", "X509", "IsCA", "RetainParentContext"}),
			[]TestCase{DeriveContextTestCase},
		},
		{
			"DeriveContext_Simulation",
			getTestTarget([]string{"AutoInit", "Simulation", "X509", "IsCA", "RetainParentContext"}),
			[]TestCase{DeriveContextSimulationTestCase},
		},
		{
			"DeriveContext_PrivilegeEscalation",
			getTestTarget([]string{"AutoInit", "X509", "IsCA"}),
			[]TestCase{DeriveContextPrivilegeEscalationTestCase},
		},
		{
			"DeriveContext_InputFlags",
			getTestTarget([]string{"AutoInit", "Simulation", "InternalDice", "InternalInfo"}),
			[]TestCase{DeriveContextInputFlagsTestCase},
		},
		{
			"DeriveContext_MaxTCIs",
			getTestTarget([]string{"AutoInit", "Simulation"}),
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
	instance.SetLocality(DPESimulatorAutoInitLocality)
	return instance
}
