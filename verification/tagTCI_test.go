// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"log"
	"testing"

	"golang.org/x/exp/slices"
)

// This file is used to test the tagTCI command by using a simulator/emulator

func GetTestTarget_TagTCI(support_needed []string) ([]TestDPEInstance, error) {

	var instances []TestDPEInstance
	var err error
	if testTargetType == EMULATOR {
		for _, support := range support_needed {
			if !slices.Contains(emulator_supports, support) {
				return nil, errors.New("Requested support is not supported in emulator")
			}
		}
		instances, err = GetEmulatorTarget(support_needed, instances)
		if err != nil {
			return nil, err
		}
		return instances, nil
	} else if testTargetType == SIMULATOR {
		instances = []TestDPEInstance{
			&DpeSimulator{exe_path: *socket_exe, supports: Support{AutoInit: true, Tagging: true}},
		}
		for _, instance := range instances {
			instance.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)
		}
		return instances, nil
	}

	return nil, errors.New("Error in creating DPE instance")

}

func TestTagTCI(t *testing.T) {

	// Added dummy support for emulator
	support_needed := []string{"AutoInit", "X509"}

	instances, err := GetTestTarget_TagTCI(support_needed)
	if err != nil {
		if err.Error() == "Requested support is not supported in emulator" {
			log.Print("Warning: Failed executing TestCertifyKey command due to unsupported request. Hence, skipping it")
			t.Skipf("Skipping the command execution")
		} else {
			log.Fatal(err)
		}
	}

	for _, instance := range instances {
		testtagTCI(instance, t)
	}

}

func testtagTCI(d TestDPEInstance, t *testing.T) {

	if d.HasPowerControl() {
		err := d.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer d.PowerOff()
	}

	client, err := NewClient256(d)
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	// Try to create the default context if isn't done automatically.
	if !d.GetSupport().AutoInit {
		initCtxResp, err := client.InitializeContext(NewInitCtxIsDefault())
		if err != nil {
			t.Fatalf("Failed to initialize default context: %v", err)
		}
		defer client.DestroyContext(NewDestroyCtx(initCtxResp.Handle, false))
	}

	tag := TCITag(12345)
	// Check to see our tag is not yet found.
	if _, err := client.GetTaggedTCI(&GetTaggedTCIReq{Tag: tag}); !errors.Is(err, StatusBadTag) {
		t.Fatalf("GetTaggedTCI returned %v, want %v", err, StatusBadTag)
	}

	// Tag the default context
	var ctx ContextHandle

	tagResp, err := client.TagTCI(&TagTCIReq{ContextHandle: ctx, Tag: tag})
	if err != nil {
		t.Fatalf("Could not tag TCI: %v", err)
	}

	if tagResp.NewContextHandle != ctx {
		t.Errorf("New context handle from TagTCI was %x, expected %x", tagResp.NewContextHandle, ctx)
	}

	getResp, err := client.GetTaggedTCI(&GetTaggedTCIReq{Tag: tag})
	if err != nil {
		t.Fatalf("Could not get tagged TCI: %v", err)
	}

	var wantCumulativeTCI SHA256Digest
	if getResp.CumulativeTCI != wantCumulativeTCI {
		t.Errorf("GetTaggedTCI returned cumulative TCI %x, expected %x", getResp.CumulativeTCI, wantCumulativeTCI)
	}

	var wantCurrentTCI SHA256Digest
	if getResp.CurrentTCI != wantCurrentTCI {
		t.Errorf("GetTaggedTCI returned current TCI %x, expected %x", getResp.CurrentTCI, wantCurrentTCI)
	}

	// Make sure some other tag is still not found.
	if _, err := client.GetTaggedTCI(&GetTaggedTCIReq{Tag: TCITag(98765)}); !errors.Is(err, StatusBadTag) {
		t.Fatalf("GetTaggedTCI returned %v, want %v", err, StatusBadTag)
	}

	// TODO: When DeriveChild is implemented, call it here to add more TCIs and call TagTCI again.
}
