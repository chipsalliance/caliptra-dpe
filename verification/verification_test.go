package verification

import (
	"flag"
	"log"
	"testing"
)

const (
	AUTO_INIT_LOCALITY uint32 = 0
	OTHER_LOCALITY     uint32 = 0x4f544852
)

var sim_exe = flag.String("sim", "../simulator/target/debug/simulator", "path to simulator executable")

func TestGetProfile(t *testing.T) {
	simulator := DpeSimulator{}
	defer simulator.Terminate()
	err := simulator.Start(*sim_exe)
	if err != nil {
		log.Fatal(err)
	}

	client := DpeClient{transport: &SimulatorTransport{}}
	err, respHdr, _ := client.GetProfile(AUTO_INIT_LOCALITY)
	if err != nil {
		t.Fatal(err)
	}
	if respHdr.Status != DPE_STATUS_SUCCESS {
		t.Fatal("Unable to get profile.")
	}
}

func TestInitializeContext(t *testing.T) {
	simulator := DpeSimulator{}
	defer simulator.Terminate()
	err := simulator.Start(*sim_exe)
	if err != nil {
		log.Fatal(err)
	}

	client := DpeClient{transport: &SimulatorTransport{}}
	err, respHdr, _ := client.GetProfile(AUTO_INIT_LOCALITY)
	if err != nil {
		t.Fatal(err)
	}
	if respHdr.Status != DPE_STATUS_SUCCESS {
		t.Fatal("Unable to get profile.")
	}

	err, respHdr, _ = client.Initialize(AUTO_INIT_LOCALITY, NewInitCtxIsDefault())
	if err != nil {
		t.Fatal(err)
	}
	if respHdr.Status != 0 {
		t.Fatal("Failed to initialize default context.")
	}
}
