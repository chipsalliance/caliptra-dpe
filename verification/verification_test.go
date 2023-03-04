package verification

import (
	"flag"
	"log"
	"testing"
)

var sim_exe = flag.String("sim", "../simulator/target/debug/simulator", "path to simulator executable")

func TestGetProfile(t *testing.T) {
	simulator := DpeSimulator{}
	defer simulator.Terminate()
	err := simulator.Start(*sim_exe)
	if err != nil {
		log.Fatal(err)
	}

	client := DpeClient{transport: &SimulatorTransport{}, profile: DPE_PROFILE_P256_SHA256}
	err, _ = client.GetProfile()
	if err != nil {
		t.Fatal(err)
	}
}

func TestInitializeContext(t *testing.T) {
	simulator := DpeSimulator{}
	defer simulator.Terminate()
	err := simulator.Start(*sim_exe)
	if err != nil {
		log.Fatal(err)
	}
	client := DpeClient{transport: &SimulatorTransport{}, profile: DPE_PROFILE_P256_SHA256}
	err, _ = client.Initialize(NewInitCtxIsDefault())
	if err != nil {
		t.Fatal(err)
	}
}
