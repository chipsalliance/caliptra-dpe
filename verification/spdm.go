// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"testing"
	"unsafe"
)

// #cgo CFLAGS: -Wall -Iexamples/spdm -Iexamples/spdm/libspdm/os_stub -Iexamples/spdm/libspdm/os_stub/spdm_device_secret_lib_sample -Iexamples/spdm/libspdm/os_stub/spdm_crypt_ext_lib -Iexamples/spdm/include -Iexamples/spdm/include/library -Iexamples/spdm/libspdm/include -Iexamples/spdm/libspdm/include/hal -Iexamples/spdm/libspdm/include/hal/library -Iexamples/spdm/libspdm/include/industry_standard -Iexamples/spdm/libspdm/include/internal -Iexamples/spdm/libspdm/include/library -Iexamples/spdm/libspdm/include/library/cryptlib -Iexamples/spdm/libspdm/include/library/requester -Iexamples/spdm/libspdm/include/library/responder -Iexamples/spdm/spdm_caliptra/spdm_caliptra_common -Iexamples/spdm/spdm_caliptra/spdm_caliptra_requester -Iexamples/spdm/spdm_caliptra/spdm_caliptra_responder -g
// #cgo LDFLAGS: -Lexamples/spdm -Lexamples/spdm/build/lib -lspdm_caliptra_requester -lspdm_requester_lib -lspdm_responder_lib -lspdm_common_lib -lspdm_transport_mctp_lib -lspdm_secured_message_lib  -lspdm_device_secret_lib_sample -lspdm_crypt_ext_lib  -lspdm_crypt_lib  -lmctp_requester_lib -lmctp_responder_lib -lmemlib  -lcryptlib_openssl -ldebuglib -lmalloclib -lopenssllib -lssl -lcrypto -lrnglib -lplatform_lib -ldebuglib_null -lspdm_transport_pcidoe_lib
// #include "examples/spdm/spdm_caliptra/spdm_caliptra_requester/spdm_caliptra_requester.h"
/*
bool platform_client_routine111(void **m_temp, size_t *cert_chain_data_size, int *a)
{
    bool result;
    *cert_chain_data_size = 2; // CHECKPOINT2
	uint8_t cert_chain[2];
    *m_temp = malloc(sizeof(unsigned char) * (*cert_chain_data_size));
	cert_chain[0]=100;
	cert_chain[1]=20;

	//*m_temp = cert_chain;

    if (NULL == *m_temp)
    {
		 *cert_chain_data_size = 3; // CHECKPOINT3
        printf("Memory allocation failed\n");
        return false;
    }
    memcpy(*m_temp, cert_chain, *cert_chain_data_size);
	*cert_chain_data_size = 4; // CHECKPOINT4

    printf("\nCHECKPOINT 10XXXXXXXXXXXXX11110XXXXXXXXXXXXX11110XXXXXXXXXXXXX11110XXXXXXXXXXXXX111");
    int i;
    int k = *cert_chain_data_size;
    printf("\nCHECKPOINT 9BBB KKKK %d\n", k);

    for (i = 0; i < *cert_chain_data_size; i++)
    {
        printf("%x ", ((uint8_t *)*m_temp)[i]);
    }

    printf("\n\n");
    for (i = 0; i < *cert_chain_data_size; i++)
    {
        printf("%d ", ((uint8_t *)*m_temp)[i]);
    }
    *cert_chain_data_size = 5; // CHECKPOINT5

    result = true;
    printf("\n%d\n", *a);
    *a = 10;
    printf("\n%d\n", *a);
    //*cert_chain_data_size = cert_chain[0]; // CHECKPOINT6
    return result;
}

int main111(void **temp, size_t *cert_chain_data_size)
{
    bool result;
    int a;
    a = 5;
    // size_t cert_chain_data_size = 0;
    // void *temp;
    unsigned char *temp1;
    //   temp = malloc(sizeof(unsigned char) * 2000);

    // cert_chain_data_size = 0;
    *cert_chain_data_size = 1; // CHECKPOINT1
    printf("\nCHECKPOINT 10AAAA %p\n", temp);
    result = platform_client_routine111(temp, cert_chain_data_size, &a);
	//*cert_chain_data_size = 7; // CHECKPOINT7

    printf("\nCHECKPOINT 10A\n");

    printf("\n%ld\n", *cert_chain_data_size);
    // printf("\n%ln\n", &cert_chain_data_size);

    temp1 = (uint8_t *)*temp;
    printf("\nCHECKPOINT 1000000000KKKKKKKKKKKKKKKKKKKKKKK %p\n", *temp);
    int i;
    for (i = 0; i < *cert_chain_data_size; i++)
    {
        printf("%x ", (uint8_t)temp1[i]);
    }
    printf("\n\n");
    for (i = 0; i < *cert_chain_data_size; i++)
    {
        printf("%d ", (uint8_t)temp1[i]);
    }
    printf("\nCHECKPOINT 10B\n");
    printf("\n%d\n", a);
	*cert_chain_data_size = (uint8_t)temp1[1]; // CHECKPOINT8
    return (!result);
}
*/
import "C"

func TestWithSpdmResponder(d TestDPEInstance, client DPEClient, t *testing.T) {
	// INCLUDE LATER?
	// -lspdm_caliptra_responder
	// #include "examples/spdm/spdm_caliptra/spdm_caliptra_responder/spdm_caliptra_responder.h"

	simulation := false

	// Get handle, digest size
	handle := getInitialContextHandle(d, client, t, simulation)

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("[FATAL]: Could not get profile: %v", err)
	}
	digestSize := profile.GetDigestSize()

	// Get cumulative before extend
	handle, tcbInfo, err := getTcbInfoForHandle(client, handle)
	if err != nil {
		t.Fatal(err)
	}
	lastCumulative := tcbInfo.Fwids[1].Digest

	// Iniitalize caller supplied TCI value
	inputData := make([]byte, digestSize)
	for i := range inputData {
		inputData[i] = byte(i)
	}

	// Extend TCI to the current context
	handle, err = client.ExtendTCI(handle, inputData)
	if err != nil {
		t.Errorf("[ERROR]: Unable to extend tci value %v", err)
	}

	// TODO: (if needed) Initialize Requester
	// TODO: Make SPDM series of calls to responder through requester
	// TODO: Get the sequence of calls (Get sequence, see libspdm.c, see sample parsing each fieeld tried initially without libspdm.c )
	// TODO: Parse the response from each call and handle appropriately
	// TODO: We need to have CertifyKey leaf cert and cert chain from responder

	var out unsafe.Pointer
	var dpeProfile = C.CString("DPE_PROFILE_IROT_P384_SHA384")
	var port = C.int(2323)
	defer C.free(out)
	//defer C.Stop()

	// fmt.Println((*unsafe.Pointer)(unsafe.Pointer(&out)))
	// fmt.Println(unsafe.Pointer(&out))
	c_certChainSize := C.uint64_t(0)
	fmt.Println(&c_certChainSize)

	//	ret := C.get_hrot_quote((*unsafe.Pointer)(unsafe.Pointer(&out[0])),
	//go C.start(C.int(1))

	status := int(C.main1(dpeProfile, port, &out, &c_certChainSize))
	cout := (*C.uint8_t)(out)
	fmt.Println(cout)
	b := C.GoBytes(unsafe.Pointer(cout), C.int(c_certChainSize))
	fmt.Println(b)
	fmt.Println(int(c_certChainSize))
	fmt.Println(status)

	certs, err := x509.ParseCertificates(b)
	fmt.Println(err)
	fmt.Println(certs)

	var out256 unsafe.Pointer
	defer C.free(out256)
	//defer C.Stop()

	// fmt.Println((*unsafe.Pointer)(unsafe.Pointer(&out)))
	// fmt.Println(unsafe.Pointer(&out))
	var dpeProfile256 = C.CString("DPE_PROFILE_IROT_P256_SHA256")
	c_certChainSize256 := C.uint64_t(0)
	fmt.Println(&c_certChainSize256)
	status256 := int(C.main1(dpeProfile256, port, &out256, &c_certChainSize256))
	cout256 := (*C.uint8_t)(out256)
	fmt.Println(cout256)
	b256 := C.GoBytes(unsafe.Pointer(cout256), C.int(c_certChainSize256))
	fmt.Println(b256)
	fmt.Println(int(c_certChainSize256))
	fmt.Println(status256)

	certs256, err := x509.ParseCertificates(b256)
	fmt.Println(err)
	fmt.Println(certs256)
	// TODO: ends

	// Get DPE certificate from SPDM
	certifyKeyResp, err := client.CertifyKey(handle, make([]byte, digestSize), CertifyKeyX509, CertifyKeyFlags(0)) // STUB, MODIFY: We need to have CertifyKey leaf cert and cert cahin from responder
	if err != nil {
		t.Fatalf("[FATAL]: Unable to obtain certificate %v", err)
	}
	dpeCertBytes := certifyKeyResp.Certificate // These bytes should be received from requester

	// Parse certificate received
	dpeCert, err := x509.ParseCertificate(dpeCertBytes)
	if err != nil {
		t.Fatalf("[FATAL]: Unable to parse DER encoded certificate %v", err)
	}

	// Get certificate chain from SPDM
	certChainBytes, err := client.GetCertificateChain() // STUB, MODIFY: We need to have Certchain from SPDM
	if err != nil {
		t.Fatalf("[FATAL]: Unable to get DER encoded certificate chain %v", err)
	}

	// Parse cert chain
	certChain, err := x509.ParseCertificates(certChainBytes)
	if err != nil {
		t.Fatalf("[FATAL]: Unable to parse DER encoded certificate %v", err)
	}

	// Validate certificate chain
	validateLeafCertChain(certChain, dpeCert)

	// Validate evidence in DPE cert MultiTCB information extension
	multiTcbInfo, err := getMultiTcbInfo(dpeCert.Extensions)
	if err != nil {
		t.Fatalf("[FATAL]: Unable to parse MultiTCB info that contains evidence %v", err)
	}
	if len(multiTcbInfo) == 0 {
		t.Fatalf("[FATAL]: Unable to validate as multi TCb information is empty")
	}

	receivedCumulative := multiTcbInfo[0].Fwids[1].Digest
	expectedCumulative := computeExpectedCumulative(lastCumulative, inputData)
	if !bytes.Equal(receivedCumulative, expectedCumulative) {
		t.Fatalf("[FATAL]: Cumulative hash from SPDM should be %v but got %v", expectedCumulative, receivedCumulative)
	} else {
		t.Log("[LOG] Received expected evidence data from Caliptra through SPDM.")
	}
	// TODO: (Explore signed measurements - stage 2)
	//cs := C.CString("HP")
	//defer C.free(unsafe.Pointer(cs))
	//C.print_spdm_caliptra_usage(cs)
	//fmt.Println(C.myreturnData(C.int(2)))
}

// -Wextra -Wfloat-equal -Wundef -Wpointer-arith -Wcast-align -Wwrite-strings -Wswitch-default -Wswitch-enum -Wunreachable-code -Wno-cast-qual -Wno-unused-variable -Wno-unused-parameter -Wno-unused-value -Wno-deprecated-declarations -Wno-incompatible-pointer-types -Wno-sign-conversion -Wno-sign-compare -Wno-cast-align -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-int-conversion -Wno-maybe-uninitialized -Wno-discarded-qualifiers -Wimplicit-function-declaration
// #include "libspdm/os_stub/memlib/zero_mem.c"
// #include "libspdm/library/spdm_common_lib/libspdm_com_context_data.c"

// // Argument received : Intialize character buffer to receive the base64 encoded string of SPDM measurements and details JSON.
// out := make([]*C.char, 1)
// cs := C.CString("")
// defer C.free(unsafe.Pointer(cs))
// out[0] = cs
// // Argument received : Initialize integer to receive the length of encoded string returned.
// size := C.int(0)

// // Function call
// // Signature of C function : get_hrot_quote(void **out, int *size, int *indices, int indices_size, uint8_t* nonce, int slot_id)
// ret := C.get_hrot_quote((*unsafe.Pointer)(unsafe.Pointer(&out[0])),
// 	&size, (*C.int)(unsafe.Pointer(&indices_c[0])),
// 	indices_size, (*C.uint8_t)(unsafe.Pointer(&nonce_c[0])), slot_id_c)

/*
// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"testing"
)

// Get Context handle
// Extend TCI using handle

// TODO: (if needed) Initialize Requester
// TODO: Make SPDM series of calls to responder through requester
// TODO: Get the sequence of calls (Get sequence, see libspdm.c, see sample parsing each fieeld tried initially without libspdm.c )
// TODO: Parse the response from each call and handle appropriately
// TODO: We need to have CertifyKey leaf cert and cert cahin from responder
// TODO: (Explore signed measurements - stage 2)

// STUB, REMOVE: We need to have CertifyKey leaf cert and cert cahin from responder
// Validate certchain in go
// Validate DiceTcb info in certify key with extended Tci
// Complet validation

// #cgo LDFLAGS:
*/

// build/out/memlib.out/CMakeFiles/memlib.dir/zero_mem.c.o

/*
- pass void **
- this is a reference to void* pointer
- how to create void* pointer and pass its address
*/
// APPROACH 01 - No error but out is filled with junk
// func main() {
// 	fmt.Println("Hi")

// 	out := []C.uint8_t{}

// 	out = append(out, C.uint8_t(0))
// 	outUnsafe := unsafe.Pointer(&out[0])
// 	// fmt.Println((*unsafe.Pointer)(unsafe.Pointer(&out)))
// 	// fmt.Println(unsafe.Pointer(&out))
// 	c_certChainSize := C.uint64_t(0)
// 	fmt.Println(&c_certChainSize)

// 	//	ret := C.get_hrot_quote((*unsafe.Pointer)(unsafe.Pointer(&out[0])),

// 	status := int(C.main111((*unsafe.Pointer)(outUnsafe), &c_certChainSize))
// 	// b := C.GoBytes(unsafe.Pointer(&out[0]), C.int(c_certChainSize))

// 	// fmt.Println(b)
// 	fmt.Println(status)
// }
