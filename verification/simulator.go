package verification

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	socketPath = "/tmp/dpe-sim.socket"
)

type DpeSimulator struct {
	cmd                     *exec.Cmd
	supports_simulation     bool
	supports_extend_tci     bool
	supports_auto_init      bool
	supports_tagging        bool
	supports_rotate_context bool
}

// Start the simulator.
func (s *DpeSimulator) Start(exe_path string) error {
	args := []string{}
	if s.supports_simulation {
		args = append(args, "--supports_simulation")
	}
	if s.supports_extend_tci {
		args = append(args, "--supports_extend_tci")
	}
	if s.supports_auto_init {
		args = append(args, "--supports_auto_init")
	}
	if s.supports_tagging {
		args = append(args, "--supports_tagging")
	}
	if s.supports_rotate_context {
		args = append(args, "--supports_rotate_context")
	}

	s.cmd = exec.Command(exe_path, args...)
	s.cmd.Stdout = os.Stdout
	err := s.cmd.Start()
	if err != nil {
		return err
	}
	if !s.waitForSimulator() {
		return errors.New("The simulator never started")
	}
	return nil
}

// Kill the terminator in a way that it can cleanup before closing.
func (s *DpeSimulator) Terminate() error {
	if s.cmd != nil {
		return s.cmd.Process.Signal(syscall.SIGTERM)
	}
	return nil
}

// Wait for the simulator to come alive. Timeout at 15 seconds.
func (s *DpeSimulator) waitForSimulator() bool {
	timeout_seconds := 15
	checks_per_sec := 4

	for i := 0; i < checks_per_sec*timeout_seconds; i++ {
		// Check if the socket file has been created.
		if fileExists(socketPath) {
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

type SimulatorTransport struct {
	Transport
}

func (s *SimulatorTransport) SendCmd(buf []byte) (error, []byte) {
	// Connect to DPE instance.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return err, []byte{}
	}

	// Send the command.
	num_sent, err := conn.Write(buf)
	if err != nil {
		return err, []byte{}
	}
	if num_sent != len(buf) {
		return errors.New("Didn't send the whole command."), []byte{}
	}

	// Get the response.
	num_rec, err := conn.Read(buf)
	if err != nil {
		return err, []byte{}
	}
	if num_rec == 0 {
		return errors.New("Didn't receive anything in the response."), []byte{}
	}

	return nil, buf
}
