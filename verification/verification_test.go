// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"testing"

	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

var sim_exe = flag.String("sim", "../simulator/target/debug/dpe-simulator", "path to simulator executable")

// An extension to the main DPE transport interface with test hooks.
type TestDPEInstance interface {
	Transport
	// If power control is unavailable for the given device, return false from
	// HasPowerControl and return an error from PowerOn and PowerOff. For devices
	// that don't support power control but do have reset capability, return true
	// from HasPowerControl leave PowerOn empty and execute the reset in PowerOff.
	HasPowerControl() bool
	// If supported, turns on the device or starts the emulator/simulator.
	PowerOn() error
	// If supported, turns of the device, stops the emulator/simulator, or resets.
	PowerOff() error
	// The Transport implementations are not expected to be able to set the values
	// it supports, but this function is used by tests to know how to test the DPE
	// instance.
	GetSupport() *Support
	// Returns the profile the transport supports.
	GetProfile() Profile
	// Returns a slice of all the localities the instance supports.
	GetSupportedLocalities() []uint32
	// Sets the current locality.
	SetLocality(locality uint32)
	// Gets the current locality.
	GetLocality() uint32
	// Returns the Maximum number of the TCIs instance can have.
	GetMaxTciNodes() uint32
	// Returns the major version of the profile the instance implements.
	GetProfileMajorVersion() uint16
	// Returns the minor version of the profile the instance implements.
	GetProfileMinorVersion() uint16
	// Returns the Vendor ID of the profile.
	GetProfileVendorId() uint32
	// Returns the vendor's product SKU.
	GetProfileVendorSku() uint32
}

func TestGetProfile(t *testing.T) {
	simulators := []TestDPEInstance{
		// No extra options.
		&DpeSimulator{exe_path: *sim_exe},
		// Supports simulation.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Simulation: true}},
		// Supports extended TCI.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{ExtendTci: true}},
		// Supports auto-init.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{AutoInit: true}},
		// Supports tagging.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Tagging: true}},
		// Supports rotate context.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{RotateContext: true}},
		// Supports certify key.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{X509: true}},
		// Supports certify csr.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Csr: true}},
		// Supports symmetric derivation.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{IsSymmetric: true}},
		// Supports internal info.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{InternalInfo: true}},
		// Supports internal DICE.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{InternalDice: true}},
		// Supports IsCA
		&DpeSimulator{exe_path: *sim_exe, supports: Support{IsCA: true}},
		// Supports a couple combos.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Simulation: true, AutoInit: true, RotateContext: true, Csr: true, InternalDice: true, IsCA: true}},
		&DpeSimulator{exe_path: *sim_exe, supports: Support{ExtendTci: true, Tagging: true, X509: true, InternalInfo: true}},
		// Supports everything.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Simulation: true, ExtendTci: true, AutoInit: true, Tagging: true, RotateContext: true, X509: true, Csr: true, IsSymmetric: true, InternalInfo: true, InternalDice: true, IsCA: true}},
	}

	for _, s := range simulators {
		testGetProfile(s, t)
	}
}

func testGetProfile(d TestDPEInstance, t *testing.T) {
	const MIN_TCI_NODES uint32 = 8
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

	for _, locality := range d.GetSupportedLocalities() {
		d.SetLocality(locality)
		rsp, err := client.GetProfile()
		if err != nil {
			t.Fatalf("Unable to get profile: %v", err)
		}
		if rsp.Profile != d.GetProfile() {
			t.Fatalf("Incorrect profile. 0x%08x != 0x%08x", d.GetProfile(), rsp.Profile)
		}
		if rsp.MajorVersion != d.GetProfileMajorVersion() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", d.GetProfileMajorVersion(), rsp.MajorVersion)
		}
		if rsp.MinorVersion != d.GetProfileMinorVersion() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", d.GetProfileMinorVersion(), rsp.MinorVersion)
		}
		if rsp.VendorId != d.GetProfileVendorId() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", d.GetProfileVendorId(), rsp.VendorId)
		}
		if rsp.VendorSku != d.GetProfileVendorSku() {
			t.Fatalf("Incorrect version. 0x%08x != 0x%08x", d.GetProfileVendorSku(), rsp.VendorSku)
		}
		if rsp.MaxTciNodes != d.GetMaxTciNodes() {
			t.Fatalf("Incorrect max TCI nodes. 0x%08x != 0x%08x", d.GetMaxTciNodes(), rsp.MaxTciNodes)
		}
		if rsp.MaxTciNodes < MIN_TCI_NODES {
			t.Fatalf("DPE instances must be able to support at least %d TCI nodes.", MIN_TCI_NODES)
		}
		if rsp.Flags != d.GetSupport().ToFlags() {
			t.Fatalf("Incorrect support flags. 0x%08x != 0x%08x", d.GetSupport().ToFlags(), rsp.Flags)
		}
	}
}

func TestInitializeContext(t *testing.T) {
	simulators := []TestDPEInstance{
		// No extra options.
		&DpeSimulator{exe_path: *sim_exe},
		// Supports simulation.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{Simulation: true}},
	}

	for _, s := range simulators {
		for _, l := range s.GetSupportedLocalities() {
			s.SetLocality(l)
			testInitContext(s, t)
		}
	}
}

func testInitContext(d TestDPEInstance, t *testing.T) {
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
		if initCtxResp.Handle != [16]byte{0} {
			t.Fatal("Incorrect default context handle.")
		}
		defer client.DestroyContext(NewDestroyCtx(initCtxResp.Handle, false))
	}

	// Try to initialize another default context.
	_, err = client.InitializeContext(NewInitCtxIsDefault())
	if err == nil {
		t.Fatal("The instance should return an error when trying to initialize another default context.")
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Try to initialize a context that is neither default or simulation.
	_, err = client.InitializeContext(&InitCtxCmd{})
	if err == nil {
		t.Fatal("The instance should return an error when not default or simulation.")
	} else if !errors.Is(err, StatusInvalidArgument) {
		t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusInvalidArgument, err)
	}

	if !d.GetSupport().Simulation {
		// Try to initialize a simulation context when they aren't supported.
		_, err = client.InitializeContext(NewInitCtxIsSimulation())
		if err == nil {
			t.Fatal("The instance should return an error when trying to initialize another default context.")
		} else if !errors.Is(err, StatusArgumentNotSupported) {
			t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusArgumentNotSupported, err)
		}
	} else {
		getProfileRsp, err := client.GetProfile()
		if err != nil {
			t.Fatalf("Failed to get profile: %v", err)
		}

		// Try to get the correct error for overflowing the contexts. Fill up the
		// rest of the contexts (-1 for default).
		for i := uint32(0); i < getProfileRsp.MaxTciNodes-1; i++ {
			initCtxResp, err := client.InitializeContext(NewInitCtxIsSimulation())
			if err != nil {
				t.Fatal("The instance should be able to create a simulation context.")
			}
			// Could prove difficult to prove it is a cryptographically secure random.
			if initCtxResp.Handle == [16]byte{0} {
				t.Fatal("Incorrect simulation context handle.")
			}
			defer client.DestroyContext(NewDestroyCtx(initCtxResp.Handle, false))
		}

		// Now try to make one more than the max.
		_, err = client.InitializeContext(NewInitCtxIsSimulation())
		if err == nil {
			t.Fatal("Failed to report an error for too many contexts.")
		} else if !errors.Is(err, StatusMaxTCIs) {
			t.Fatalf("Incorrect error type. Should return %q, but returned %q", StatusMaxTCIs, err)
		}
	}
}

func TestCertifyKey(t *testing.T) {
	simulators := []TestDPEInstance{
		// No extra options besides AutoInit.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{AutoInit: true, X509: true}},
		// Supports AutoInit and simulation contexts.
		&DpeSimulator{exe_path: *sim_exe, supports: Support{AutoInit: true, Simulation: true, X509: true}},
	}

	for _, s := range simulators {
		s.SetLocality(DPE_SIMULATOR_AUTO_INIT_LOCALITY)
		testCertifyKey(s, t)
	}
}

func checkCertificateStructure(t *testing.T, certData []byte) {
	t.Helper()
	failed := false

	// Most likely redundant with zx509 check below, but check that the regular x509 library can parse the cert.
	if _, err := x509.ParseCertificate(certData); err != nil {
		t.Fatalf("Could not parse certificate using crypto/x509: %v", err)
		failed = true
	}

	// Parse the cert with zcrypto so we can lint it.
	cert, err := zx509.ParseCertificate(certData)
	if err != nil {
		t.Errorf("Could not parse certificate using zcrypto/x509: %v", err)
		failed = true
	}

	// zlint provides a lot of linter sources. Limit results to just the relevant RFCs.
	// For a full listing of supported linter sources, see https://github.com/zmap/zlint/blob/master/v3/lint/source.go
	registry, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		IncludeSources: lint.SourceList{
			lint.RFC3279,
			lint.RFC5280,
			lint.RFC5480,
			lint.RFC5891,
			lint.RFC8813,
		}})
	if err != nil {
		t.Fatalf("Could not set up zlint registry: %v", err)
	}

	results := zlint.LintCertificateEx(cert, registry)

	for id, result := range results.Results {
		var level string
		switch result.Status {
		case lint.Error:
			level = "ERROR"
		case lint.Warn:
			level = "WARN"
		default:
			continue
		}
		details := result.Details
		if details != "" {
			details = fmt.Sprintf("%s. ", details)
		}
		l := registry.ByName(id)
		// TODO(https://github.com/chipsalliance/caliptra-dpe/issues/74):
		// Fail the test with Errorf here once we expect it to pass.
		t.Logf("[%s] %s: %s%s (%s)", level, l.Source, details, l.Description, l.Citation)
		failed = true
	}

	if failed {
		// Dump the cert in PEM and hex for use with various tools
		t.Logf("Offending certificate (PEM):\n%s", (string)(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certData,
		})))
		t.Logf("Offending certificate (DER):\n%x", certData)
	}
}

func testCertifyKey(d TestDPEInstance, t *testing.T) {
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

	certifyKeyReq := CertifyKeyReq[SHA256Digest]{
		ContextHandle: [16]byte{0},
		Flags:         0,
		Label:         [32]byte{0},
		Format:        CertifyKeyX509,
	}

	certifyKeyResp, err := client.CertifyKey(&certifyKeyReq)
	if err != nil {
		t.Fatalf("Could not certify key: %v", err)
	}
	checkCertificateStructure(t, certifyKeyResp.Certificate)

	// TODO: When DeriveChild is implemented, call it here to add more TCIs and call CertifyKey again.
}

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
