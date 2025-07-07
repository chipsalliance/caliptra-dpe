// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
)

// InvalidHandle is a sample DPE handle which is very unlikely to be valid
var InvalidHandle = client.ContextHandle{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// TestInvalidHandle checks whether error is reported when non-existent handle
// is passed as input to DPE commands.
// Exceptions are - GetProfile, InitializeContext, GetCertificateChain, commands
// which do not need context handle as input parameter.
func TestInvalidHandle(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	ctx := getInitialContextHandle(d, c, t, true)
	defer c.DestroyContext(ctx)

	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	// Check DeriveContext with invalid handle
	if _, err := c.DeriveContext(&InvalidHandle, make([]byte, digestLen), 0, 0, 0); err == nil {
		t.Errorf("[ERROR]: DeriveContext should return %q, but returned no error", client.StatusInvalidHandle)
	} else if !errors.Is(err, client.StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. DeriveContext should return %q, but returned %q", client.StatusInvalidHandle, err)
	}

	// Check CertifyKey with invalid handle
	if _, err := c.CertifyKey(&InvalidHandle, make([]byte, digestLen), 0, 0); err == nil {
		t.Errorf("[ERROR]: CertifyKey should return %q, but returned no error", client.StatusInvalidHandle)
	} else if !errors.Is(err, client.StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. CertifyKey should return %q, but returned %q", client.StatusInvalidHandle, err)
	}

	// Check Sign with invalid handle
	if _, err := c.Sign(&InvalidHandle, make([]byte, digestLen), 0, make([]byte, digestLen)); err == nil {
		t.Errorf("[ERROR]: Sign should return %q, but returned no error", client.StatusInvalidHandle)
	} else if !errors.Is(err, client.StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. Sign should return %q, but returned %q", client.StatusInvalidHandle, err)
	}

	// Check RotateContextHandle with invalid handle
	if _, err := c.RotateContextHandle(&InvalidHandle, client.RotateContextHandleFlags(client.TargetIsDefault)); err == nil {
		t.Errorf("[ERROR]: RotateContextHandle should return %q, but returned no error", client.StatusInvalidHandle)
	} else if !errors.Is(err, client.StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. RotateContextHandle should return %q, but returned %q", client.StatusInvalidHandle, err)
	}

	// Check DestroyContext with invalid handle
	if err := c.DestroyContext(&InvalidHandle); err == nil {
		t.Errorf("[ERROR]: DestroyContext should return %q, but returned no error", client.StatusInvalidHandle)
	} else if !errors.Is(err, client.StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. DestroyContext should return %q, but returned %q", client.StatusInvalidHandle, err)
	}
}

// TestWrongLocality checks whether error is reported when caller from one
// locality issues DPE commands in another locality.
// Exceptions are - GetProfile, InitializeContext, GetCertificateChain, commands
// which do not need context handle as input and hence locality is irrelevant.
func TestWrongLocality(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	if !d.HasLocalityControl() {
		t.Skipf("Target does not have locality control")
	}

	// Modify and later restore the locality of DPE instance to test
	currentLocality := d.GetLocality()
	d.SetLocality(currentLocality + 1)
	defer d.SetLocality(currentLocality)

	// Get default context handle
	handle := &client.DefaultContextHandle

	// Get digest size
	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()

	// Check DeriveContext from wrong context
	if _, err := c.DeriveContext(handle, make([]byte, digestLen), 0, 0, 0); err == nil {
		t.Errorf("[ERROR]: DeriveContext should return %q, but returned no error", client.StatusInvalidLocality)
	} else if !errors.Is(err, client.StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. DeriveContext should return %q, but returned %q", client.StatusInvalidLocality, err)
	}

	// Check CertifyKey from wrong locality
	if _, err := c.CertifyKey(handle, make([]byte, digestLen), 0, 0); err == nil {
		t.Errorf("[ERROR]: CertifyKey should return %q, but returned no error", client.StatusInvalidLocality)
	} else if !errors.Is(err, client.StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. CertifyKey should return %q, but returned %q", client.StatusInvalidLocality, err)
	}

	// Check Sign from wrong locality
	if _, err := c.Sign(handle, make([]byte, digestLen), 0, make([]byte, digestLen)); err == nil {
		t.Errorf("[ERROR]: Sign should return %q, but returned no error", client.StatusInvalidLocality)
	} else if !errors.Is(err, client.StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. Sign should return %q, but returned %q", client.StatusInvalidLocality, err)
	}

	// Check RotateContextHandle from wrong locality
	if _, err := c.RotateContextHandle(handle, client.RotateContextHandleFlags(client.TargetIsDefault)); err == nil {
		t.Errorf("[ERROR]: RotateContextHandle should return %q, but returned no error", client.StatusInvalidLocality)
	} else if !errors.Is(err, client.StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. RotateContextHandle should return %q, but returned %q", client.StatusInvalidLocality, err)
	}

	// Check DestroyContext from wrong locality
	if err := c.DestroyContext(handle); err == nil {
		t.Errorf("[ERROR]: DestroyContext should return %q, but returned no error", client.StatusInvalidLocality)
	} else if !errors.Is(err, client.StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. DestroyContext should return %q, but returned %q", client.StatusInvalidLocality, err)
	}
}

// TestUnsupportedCommand checks whether error is reported while using commands
// that are turned off in DPE.
// DPE commands - RotateContextHandle requires support to be enabled in DPE profile
// before being called.
func TestUnsupportedCommand(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	ctx := &client.DefaultContextHandle

	// Check whether RotateContextHandle is unsupported by DPE profile
	if _, err := c.RotateContextHandle(ctx, client.RotateContextHandleFlags(client.TargetIsDefault)); err == nil {
		t.Errorf("[ERROR]: RotateContextHandle is not supported by DPE, should return %q, but returned no error", client.StatusInvalidCommand)
	} else if !errors.Is(err, client.StatusInvalidCommand) {
		t.Errorf("[ERROR]: Incorrect error type. RotateContextHandle is not supported by DPE, should return %q, but returned %q", client.StatusInvalidCommand, err)
	}
}

// TestUnsupportedCommandFlag checks whether error is reported while enabling
// command flags that are turned off in DPE.
// The DPE command may be available but some of its flags may not be supported by DPE.
// DPE profile supports the below attributes.
// Simulation	: Allows caller to request for context initialization in simulation mode
// Csr 			: Allows caller to request the key cert in CSR format
// X509 		: Allows caller to request the key cert in X509 format
// InternalInfo	: Allows caller to derive child context with InternalInfo
// InternalDice	: Allows caller to derive child context with InternalDice
func TestUnsupportedCommandFlag(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	handle := &client.DefaultContextHandle

	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	// Check whether error is returned since simulation context initialization is unsupported by DPE profile
	if _, err := c.InitializeContext(client.InitIsSimulation); err == nil {
		t.Errorf("[ERROR]: Simulation is not supported by DPE, InitializeContext should return %q, but returned no error", client.StatusArgumentNotSupported)
	} else if !errors.Is(err, client.StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. Simulation is not supported by DPE, InitializeContext supported by DPE, should return %q, but returned %q", client.StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since CSR format is unsupported by DPE profile
	if _, err := c.CertifyKey(handle, make([]byte, digestLen), client.CertifyKeyCsr, 0); err == nil {
		t.Errorf("[ERROR]: CSR format is not supported by DPE, CertifyKey should return %q, but returned no error", client.StatusArgumentNotSupported)
	} else if !errors.Is(err, client.StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. CSR format is not supported by DPE, CertifyKey should return %q, but returned %q", client.StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since X509 format is unsupported by DPE profile
	if _, err := c.CertifyKey(handle, make([]byte, digestLen), client.CertifyKeyX509, 0); err == nil {
		t.Errorf("[ERROR]: X509 format is not supported by DPE, CertifyKey should return %q, but returned no error", client.StatusArgumentNotSupported)
	} else if !errors.Is(err, client.StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. X509 format is not supported by DPE, CertifyKey should return %q, but returned %q", client.StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since InternalInfo usage is unsupported by DPE profile
	if _, err := c.DeriveContext(handle, make([]byte, digestLen), client.DeriveContextFlags(client.InternalInputInfo), 0, 0); err == nil {
		t.Errorf("[ERROR]:InternalInfo is not supported by DPE, DeriveContext should return %q, but returned no error", client.StatusArgumentNotSupported)
	} else if !errors.Is(err, client.StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. InternalInfo is not supported by DPE, DeriveContext should return %q, but returned %q", client.StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since InternalDice usage is unsupported by DPE profile
	if _, err := c.DeriveContext(handle, make([]byte, digestLen), client.DeriveContextFlags(client.InternalInputDice), 0, 0); err == nil {
		t.Errorf("[ERROR]:InternalDice is not supported by DPE, DeriveContext should return %q, but returned no error", client.StatusArgumentNotSupported)
	} else if !errors.Is(err, client.StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. InternalDice is not supported by DPE, DeriveContext should return %q, but returned %q", client.StatusArgumentNotSupported, err)
	}
}
