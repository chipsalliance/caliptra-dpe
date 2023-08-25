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
	"syscall"
	"time"
)

// Added the dummy path and flags
const (
	emulatorSocketPath = "/tmp/dpe-emu.socket"

	DPE_EMULATOR_AUTO_INIT_LOCALITY    uint32  = 0
	DPE_EMULATOR_OTHER_LOCALITY        uint32  = 0
	DPE_EMULATOR_PROFILE               Profile = 0
	DPE_EMULATOR_MAX_TCI_NODES         uint32  = 0
	DPE_EMULATOR_MAJOR_PROFILE_VERSION uint16  = 0
	DPE_EMULATOR_MINOR_PROFILE_VERSION uint16  = 0
	DPE_EMULATOR_VENDOR_ID             uint32  = 0
	DPE_EMULATOR_VENDOR_SKU            uint32  = 0
)

// Added dummy support for emulator .This is to verify against the support_needed list
var emulator_supports = []string{"AutoInit", "X509"}

//TODO code for emulator to start, stop, getsupport

type DpeEmulator struct {
	exe_path        string
	cmd             *exec.Cmd
	supports        Support
	currentLocality uint32
	Transport
}

// Emulator can be started and stopped.
func (s *DpeEmulator) HasPowerControl() bool {
	return true
}

// Start the Emulator.
func (s *DpeEmulator) PowerOn() error {
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
	if s.supports.Tagging {
		args = append(args, "--supports-tagging")
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

// Kill the emulator in a way that it can cleanup before closing.
func (s *DpeEmulator) PowerOff() error {
	if s.cmd != nil {
		err := s.cmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			return err
		}
		if !s.waitForPower( /*on=*/ false) {
			return errors.New("the emulator never stopped")
		}
	}
	return nil
}

// Wait for the emulator to come alive. Timeout at 15 seconds.
func (s *DpeEmulator) waitForPower(on bool) bool {
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

func (s *DpeEmulator) SendCmd(buf []byte) ([]byte, error) {
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

func (s *DpeEmulator) GetSupport() *Support {
	return &s.supports
}

func (s *DpeEmulator) GetProfile() Profile {
	return DPE_SIMULATOR_PROFILE
}

func (s *DpeEmulator) GetSupportedLocalities() []uint32 {
	return []uint32{DPE_SIMULATOR_AUTO_INIT_LOCALITY, DPE_SIMULATOR_OTHER_LOCALITY}
}

func (s *DpeEmulator) SetLocality(locality uint32) {
	s.currentLocality = locality
}

func (s *DpeEmulator) GetLocality() uint32 {
	return s.currentLocality
}

func (s *DpeEmulator) GetMaxTciNodes() uint32 {
	return DPE_EMULATOR_MAX_TCI_NODES
}

func (s *DpeEmulator) GetProfileMajorVersion() uint16 {
	return DPE_EMULATOR_MAJOR_PROFILE_VERSION
}

func (s *DpeEmulator) GetProfileMinorVersion() uint16 {
	return DPE_EMULATOR_MINOR_PROFILE_VERSION
}

func (s *DpeEmulator) GetProfileVendorId() uint32 {
	return DPE_EMULATOR_VENDOR_ID
}

func (s *DpeEmulator) GetProfileVendorSku() uint32 {
	return DPE_EMULATOR_VENDOR_SKU
}
