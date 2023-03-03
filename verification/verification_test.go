package verification

import (
	"testing"
)

func TestGetProfile(t *testing.T) {
	client := DpeClient{transport: &SimulatorTransport{}, profile: DPE_PROFILE_P256_SHA256}
	err, _ := client.GetProfile()
	if err != nil {
		t.Fatal(err)
	}
}

func TestInitializeContext(t *testing.T) {
	client := DpeClient{transport: &SimulatorTransport{}, profile: DPE_PROFILE_P256_SHA256}
	err, _ := client.Initialize(NewInitCtxIsDefault())
	if err != nil {
		t.Fatal(err)
	}
}
