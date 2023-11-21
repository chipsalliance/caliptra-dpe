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
)

const (
	simulatorSocketPath = "/tmp/dpe-sim.socket"

	DPE_SIMULATOR_AUTO_INIT_LOCALITY    uint32 = 0
	DPE_SIMULATOR_OTHER_LOCALITY        uint32 = 0x4f544852
	DPE_SIMULATOR_MAX_TCI_NODES         uint32 = 24
	DPE_SIMULATOR_MAJOR_PROFILE_VERSION uint16 = CURRENT_PROFILE_MAJOR_VERSION
	DPE_SIMULATOR_MINOR_PROFILE_VERSION uint16 = CURRENT_PROFILE_MINOR_VERSION
	DPE_SIMULATOR_VENDOR_ID             uint32 = 0
	DPE_SIMULATOR_VENDOR_SKU            uint32 = 0
)

var TargetExe *string

type DpeSimulator struct {
	exe_path        string
	cmd             *exec.Cmd
	supports        Support
	currentLocality uint32
	isInitialized   bool
	Transport
}

// Simulator can be started and stopped.
func (s *DpeSimulator) HasPowerControl() bool {
	return true
}

// Start the simulator.
func (s *DpeSimulator) PowerOn() error {
	args := []string{}
	if s.supports.Simulation {
		args = append(args, "--supports-simulation")
	}
	if s.supports.ExtendTci {
		args = append(args, "--supports-extend-tci")
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

	s.cmd = exec.Command(s.exe_path, args...)
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

// Kill the simulator in a way that it can cleanup before closing.
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
	timeout_seconds := 15
	checks_per_sec := 50

	for i := 0; i < checks_per_sec*timeout_seconds; i++ {
		// Check if the socket file has been created.
		if fileExists(simulatorSocketPath) == on {
			return true
		}
		time.Sleep(time.Duration(1000/checks_per_sec) * time.Millisecond)
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
	num_sent, err := conn.Write(prepended.Bytes())
	if err != nil {
		return nil, err
	}
	if num_sent != len(prepended.Bytes()) {
		return nil, errors.New("didn't send the whole command")
	}

	// Get the response.
	return io.ReadAll(conn)
}

func (s *DpeSimulator) GetSupport() *Support {
	return &s.supports
}

func (s *DpeSimulator) GetIsInitialized() bool {
	return s.supports.AutoInit || s.isInitialized
}

func (s *DpeSimulator) SetIsInitialized(isInitialized bool) {
	s.isInitialized = isInitialized
}

func (s *DpeSimulator) GetSupportedLocalities() []uint32 {
	return []uint32{DPE_SIMULATOR_AUTO_INIT_LOCALITY, DPE_SIMULATOR_OTHER_LOCALITY}
}

func (s *DpeSimulator) HasLocalityControl() bool {
	return true
}

func (s *DpeSimulator) SetLocality(locality uint32) {
	s.currentLocality = locality
}

func (s *DpeSimulator) GetLocality() uint32 {
	return s.currentLocality
}

func (s *DpeSimulator) GetMaxTciNodes() uint32 {
	return DPE_SIMULATOR_MAX_TCI_NODES
}

func (s *DpeSimulator) GetProfileMajorVersion() uint16 {
	return DPE_SIMULATOR_MAJOR_PROFILE_VERSION
}

func (s *DpeSimulator) GetProfileMinorVersion() uint16 {
	return DPE_SIMULATOR_MINOR_PROFILE_VERSION
}

func (s *DpeSimulator) GetProfileVendorId() uint32 {
	return DPE_SIMULATOR_VENDOR_ID
}

func (s *DpeSimulator) GetProfileVendorSku() uint32 {
	return DPE_SIMULATOR_VENDOR_SKU
}

// Get the simulator target
func GetSimulatorTarget(support_needed []string, target_exe string) TestDPEInstance {

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
	var instance TestDPEInstance = &DpeSimulator{exe_path: target_exe, supports: support}
	return instance
}

func GetSimulatorTargets() []TestTarget {
	return []TestTarget{
		{
			"SupportNone",
			getTestTarget([]string{}),
			[]TestCase{GetProfileTestCase, InitializeContextTestCase},
		},
		{
			"DefaultSupport",
			getTestTarget([]string{"AutoInit", "Simulation", "X509", "IsCA", "RotateContext", "ExtendTci"}),
			AllTestCases,
		},
		{
			"GetProfile_Simulation",
			getTestTarget([]string{"Simulation"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_ExtendTCI",
			getTestTarget([]string{"ExtendTci"}),
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
			"GetProfile_Combo01",
			getTestTarget([]string{"Simulation", "AutoInit", "RotateContext", "Csr", "InternalDice", "IsCA"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_Combo02",
			getTestTarget([]string{"ExtendTci", "X509", "InternalInfo"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"GetProfile_All",
			getTestTarget([]string{"Simulation", "ExtendTci", "AutoInit", "RotateContext", "X509", "Csr", "IsSymmetric", "InternalInfo", "InternalDice", "IsCA"}),
			[]TestCase{GetProfileTestCase},
		},
		{
			"NegativeCase_UnsupportedCommandByDPE",
			getTestTarget([]string{"AutoInit"}),
			[]TestCase{UnsupportedCommand},
		},
		{
			"NegativeCase_UnsupportedFeatureByDPE",
			getTestTarget([]string{"AutoInit", "RotateContext", "ExtendTci"}),
			[]TestCase{UnsupportedCommandFlag},
		},
	}
}

// Get the test target for simulator/emulator
func getTestTarget(supportNeeded []string) TestDPEInstance {
	instance := GetSimulatorTarget(supportNeeded, *TargetExe)
	instance.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)
	return instance
}
