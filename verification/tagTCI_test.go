// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"log"
	"testing"
)

// This file is used to test the tagTCI command by using a simulator

func TestTagTCI(t *testing.T) {
	s := &DpeSimulator{exe_path: *sim_exe, supports: Support{AutoInit: true, Tagging: true}}
	s.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)
	if s.HasPowerControl() {
		err := s.PowerOn()
		if err != nil {
			log.Fatal(err)
		}
		defer s.PowerOff()
	}

	client, err := NewClient256(s)
	if err != nil {
		t.Fatalf("Could not initialize client: %v", err)
	}

	// Try to create the default context if isn't done automatically.
	if !s.GetSupport().AutoInit {
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
