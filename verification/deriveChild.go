// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"testing"
)

var existingTciNodeCount = 0

func TestDeriveChild(d TestDPEInstance, c DPEClient, t *testing.T) {
	// A tci node is already created at time of auto-initialization
	existingTciNodeCount += 1
	testDeriveChild(d, c, t)
}

func testDeriveChild(d TestDPEInstance, c DPEClient, t *testing.T) {
	handle := &DefaultContextHandle

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()

	// Test wrong locality

	testDeriveChildWrongLocality(t, d, c, handle, digestLen)

	// Test child handles when MakeDefault flag is enabled/disabled
	testChildHandles(t, d, c, handle, digestLen)

	// Test enabling MakeDefault flag
	testMakeDefault(t, d, c, handle, digestLen)

	// Test child handle creation in other locality.
	testMakeDefaultInNonDefaultContext(t, d, c, handle, digestLen)

	// Test Privilege escalation
	testPrivilegeEscalation(t, d, c, handle, digestLen)

	// Test for error while retaining parent handle in default context
	testRetainParentInDefaultContext(t, d, c, handle, digestLen)

	// Test retention of parent handle in non default context
	testRetainParentInNonDefaultContext(t, d, c, handle, digestLen)

	// Test enabling MakeDefault and RetainParent flags
	testRetainParentAndMakeDefault(t, d, c, handle, digestLen)

	// Test derive child contexts count limited by MAX_TCI_NODES supported by the profile
	testMaxTcis(t, d, c, handle, digestLen)
}

// Checks whether caller from one locality is prevented from making DPE calls to other locality
func testDeriveChildWrongLocality(t *testing.T, d TestDPEInstance, c DPEClient, handle *ContextHandle, digestLen int) {

	var err error

	// Modify locality of DPE instance to test
	d.SetLocality(DPE_SIMULATOR_OTHER_LOCALITY)

	// Restore locality of DPE instance after the test
	defer d.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)

	_, err = c.DeriveChild(handle,
		make([]byte, digestLen),
		DeriveChildFlags(MakeDefault),
		0,
		DPE_SIMULATOR_AUTO_INIT_LOCALITY)

	if err == nil {
		t.Fatalf("[FATAL]: Should return %q, but returned no error", StatusInvalidLocality)
	} else if !errors.Is(err, StatusInvalidLocality) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusInvalidLocality, err)
	}
}

// Check handle of default and non-default child
func testChildHandles(t *testing.T, d TestDPEInstance, c DPEClient, handle *ContextHandle, digestLen int) {
	// MakeDefault flag is not set
	r, err := c.DeriveChild(handle,
		make([]byte, digestLen),
		ChangeLocality,
		0,
		DPE_SIMULATOR_OTHER_LOCALITY)

	if err != nil {
		t.Fatalf("[FATAL]: Error while creating non-default child context handle: %s", err)
	}

	if r.NewContextHandle == DefaultContextHandle {
		t.Errorf("[ERROR]: Incorrect handle. Should return random handle, but returned %q", &DefaultContextHandle)
	}

	// Increment TCI node count, this is will be used in validating maximum allowed TCI nodes.
	existingTciNodeCount += 1

	// MakeDefault flag is set
	d.SetLocality(DPE_SIMULATOR_OTHER_LOCALITY)
	defer d.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)
	r, err = c.DeriveChild(&r.NewContextHandle,
		make([]byte, digestLen),
		MakeDefault|ChangeLocality,
		0,
		DPE_SIMULATOR_AUTO_INIT_LOCALITY,
	)

	if err != nil {
		t.Fatalf("[FATAL]: Error while creating default child context: %s", err)
	}

	if r.NewContextHandle != DefaultContextHandle {
		t.Errorf("[ERROR]: Incorrect handle. Should return %q, but returned %q", DefaultContextHandle, r.NewContextHandle)
	}

	// Increment TCI node count, this is will be used in validating maximum allowed TCI nodes.
	existingTciNodeCount += 1
}

// Checks whether the new context handle could be made the default handle by
// setting MakeDefault flag in default context.
func testMakeDefault(t *testing.T, d TestDPEInstance, c DPEClient, handle *ContextHandle, digestLen int) {
	resp, err := c.DeriveChild(handle,
		make([]byte, digestLen),
		MakeDefault,
		0,
		DPE_SIMULATOR_AUTO_INIT_LOCALITY)
	if err != nil {
		t.Fatalf("[FATAL]: Error while setting child handle as default: %s", err)
	}

	if resp.NewContextHandle != DefaultContextHandle {
		t.Errorf("[FATAL]: The child handle is not set as default handle despite enabling MakeDefault flag: %s", err)
	}

	// Increment TCI node count, this is will be used in validating maximum allowed TCI nodes.
	existingTciNodeCount += 1
}

// Checks default child handle creation in other locality.
func testMakeDefaultInNonDefaultContext(t *testing.T, d TestDPEInstance, c DPEClient, handle *ContextHandle, digestLen int) {

	r, err := c.DeriveChild(handle,
		make([]byte, digestLen),
		MakeDefault|ChangeLocality,
		0,
		DPE_SIMULATOR_OTHER_LOCALITY)

	if err != nil {
		t.Fatalf("[FATAL]: Error while creating default child handle in non-default context: %s", err)
	}

	// Increment TCI node count, this is will be used in validating maximum allowed TCI nodes.
	existingTciNodeCount += 1

	// Revert hardware locality and handle for further tests
	d.SetLocality(DPE_SIMULATOR_OTHER_LOCALITY)
	defer d.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)

	_, err = c.DeriveChild(&r.NewContextHandle,
		make([]byte, digestLen),
		MakeDefault|ChangeLocality,
		0,
		DPE_SIMULATOR_AUTO_INIT_LOCALITY)

	if err != nil {
		t.Fatalf("[FATAL]: Error while creating default child handle in default context: %s", err)
	}

	// Increment TCI node count, this is will be used in validating maximum allowed TCI nodes.
	existingTciNodeCount += 1
}

// Checks whether the derived context does not escalate beyond the privileges of parent context.
func testPrivilegeEscalation(t *testing.T, d TestDPEInstance, c DPEClient, handle *ContextHandle, digestLen int) {
	var err error
	escalatedChildPrivileges := []DeriveChildFlags{InputAllowCA, InputAllowX509}

	for _, flag := range escalatedChildPrivileges {
		_, err = c.DeriveChild(handle, make([]byte, digestLen), MakeDefault|flag, 0, 0)
		if err == nil {
			t.Fatalf("[FATAL]: Should return %q, but returned no error", StatusArgumentNotSupported)
		} else if !errors.Is(err, StatusArgumentNotSupported) {
			t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusArgumentNotSupported, err)
		}
	}
}

// Checks whether default context does not retain parent handle.
// This is because mixture of default and non-default handles are not allowed in this context.
// Parent handle is invalidated in default context.
func testRetainParentInDefaultContext(t *testing.T, d TestDPEInstance, c DPEClient, handle *ContextHandle, digestLen int) {
	_, err := c.DeriveChild(handle,
		make([]byte, digestLen),
		RetainParent,
		0,
		DPE_SIMULATOR_AUTO_INIT_LOCALITY)
	if err == nil {
		t.Fatalf("[FATAL]: Should return %q, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}
}

// Checks whether parent handle could be retained in a locality with non-default context.
func testRetainParentInNonDefaultContext(t *testing.T, d TestDPEInstance, c DPEClient, handle *ContextHandle, digestLen int) {
	_, err := c.DeriveChild(handle,
		make([]byte, digestLen),
		RetainParent|ChangeLocality,
		0,
		DPE_SIMULATOR_OTHER_LOCALITY)
	if err != nil {
		t.Fatalf("[FATAL]: Error while retaining parent handle in non-default context: %s", err)
	}

	// Increment TCI node count, this is will be used in validating maximum allowed TCI nodes.
	existingTciNodeCount += 1
}

// Checks whether error is returned when RetainParent and MakeDefault flags are used together in presence of
// default context handle. This should fail because RetainParent flag and MakeDefault when used together
// tries to create two default context handles in the locality which is not allowed since a locality can have
// only one default context handle.
func testRetainParentAndMakeDefault(t *testing.T, d TestDPEInstance, c DPEClient, handle *ContextHandle, digestLen int) {
	_, err := c.DeriveChild(handle,
		make([]byte, digestLen),
		RetainParent|ChangeLocality|MakeDefault,
		0,
		DPE_SIMULATOR_OTHER_LOCALITY)
	if err == nil {
		t.Fatalf("[FATAL]: Error while retaining parent handle and making it default in non-default context: %s", err)
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}
}

// Checks whether the number of derived contexts (TCI nodes) are limited by MAX_TCI_NODES attribute of the profile
func testMaxTcis(t *testing.T, d TestDPEInstance, c DPEClient, handle *ContextHandle, digestLen int) {

	maxTciCount := d.GetMaxTciNodes()
	allowedTciNodes := int(maxTciCount) - existingTciNodeCount

	for i := 0; i < allowedTciNodes; i++ {
		resp, err := c.DeriveChild(handle,
			make([]byte, digestLen),
			DeriveChildFlags(MakeDefault),
			0,
			DPE_SIMULATOR_AUTO_INIT_LOCALITY,
		)

		if err != nil {
			t.Fatalf("[FATAL]: Error encountered in executing derive child: %v", err)
		}
		handle = &resp.NewContextHandle
	}

	// Exceed the Max TCI node count limit
	_, err := c.DeriveChild(handle,
		make([]byte, digestLen),
		DeriveChildFlags(MakeDefault),
		0,
		DPE_SIMULATOR_AUTO_INIT_LOCALITY,
	)

	if err == nil {
		t.Fatalf("[FATAL]: Should return %q, but returned no error", StatusMaxTCIs)
	} else if !errors.Is(err, StatusMaxTCIs) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", StatusMaxTCIs, err)
	}
}
