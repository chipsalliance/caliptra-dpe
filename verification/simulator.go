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

const (
	simulatorSocketPath = "/tmp/dpe-sim.socket"

	DPE_SIMULATOR_AUTO_INIT_LOCALITY    uint32  = 0
	DPE_SIMULATOR_OTHER_LOCALITY        uint32  = 0x4f544852
	DPE_SIMULATOR_PROFILE               Profile = ProfileP256SHA256
	DPE_SIMULATOR_MAX_TCI_NODES         uint32  = 24
	DPE_SIMULATOR_MAJOR_PROFILE_VERSION uint16  = CURRENT_PROFILE_MAJOR_VERSION
	DPE_SIMULATOR_MINOR_PROFILE_VERSION uint16  = CURRENT_PROFILE_MINOR_VERSION
	DPE_SIMULATOR_VENDOR_ID             uint32  = 0
	DPE_SIMULATOR_VENDOR_SKU            uint32  = 0
)

type DpeInstance struct {
	exe_path        string
	cmd             *exec.Cmd
	supports        Support
	currentLocality uint32
	Transport
}

// Simulator can be started and stopped.
func (s *DpeInstance) HasPowerControl() bool {
	return true
}

// Start the simulator.
func (s *DpeInstance) PowerOn() error {
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

// Kill the simulator in a way that it can cleanup before closing.
func (s *DpeInstance) PowerOff() error {
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
func (s *DpeInstance) waitForPower(on bool) bool {
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

func (s *DpeInstance) SendCmd(buf []byte) ([]byte, error) {
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

func (s *DpeInstance) GetSupport() *Support {
	return &s.supports
}

func (s *DpeInstance) GetProfile() Profile {
	return DPE_SIMULATOR_PROFILE
}

func (s *DpeInstance) GetSupportedLocalities() []uint32 {
	return []uint32{DPE_SIMULATOR_AUTO_INIT_LOCALITY, DPE_SIMULATOR_OTHER_LOCALITY}
}

func (s *DpeInstance) SetLocality(locality uint32) {
	s.currentLocality = locality
}

func (s *DpeInstance) GetLocality() uint32 {
	return s.currentLocality
}

func (s *DpeInstance) GetMaxTciNodes() uint32 {
	return DPE_SIMULATOR_MAX_TCI_NODES
}

func (s *DpeInstance) GetProfileMajorVersion() uint16 {
	return DPE_SIMULATOR_MAJOR_PROFILE_VERSION
}

func (s *DpeInstance) GetProfileMinorVersion() uint16 {
	return DPE_SIMULATOR_MINOR_PROFILE_VERSION
}

func (s *DpeInstance) GetProfileVendorId() uint32 {
	return DPE_SIMULATOR_VENDOR_ID
}

func (s *DpeInstance) GetProfileVendorSku() uint32 {
	return DPE_SIMULATOR_VENDOR_SKU
}
