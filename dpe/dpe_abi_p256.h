// Licensed under the Apache-2.0 license

#ifndef MAX_CERT_SIZE
#ifdef DPE_PROFILE_HYBRID
#define MAX_CERT_SIZE (22 * 1024)
#else
#define MAX_CERT_SIZE (11 * 1024)
#endif
#endif

#ifndef MAX_EXPORTED_CDI_SIZE
#define MAX_EXPORTED_CDI_SIZE 32
#endif

#ifndef MAX_CHUNK_SIZE
#define MAX_CHUNK_SIZE 2048
#endif

#ifndef SIZE
#define SIZE 16
#endif


#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif


#define MAX_HANDLES 64

#define TCI_SIZE 32



#define Command_GET_PROFILE 1

#define Command_INITIALIZE_CONTEXT 7

#define Command_DERIVE_CONTEXT 8

#define Command_CERTIFY_KEY 9

#define Command_SIGN 10

#define Command_ROTATE_CONTEXT_HANDLE 14

#define Command_DESTROY_CONTEXT 15

#define Command_GET_CERTIFICATE_CHAIN 16

/**
 * Vendor command: UpdateContextMeasurement (first vendor slot per the iROT profile spec).
 */
#define Command_UPDATE_CONTEXT_MEASUREMENT 2147483648

#define CertifyKeyCommand_FORMAT_X509 0

#define CertifyKeyCommand_FORMAT_CSR 1

#define Context_ROOT_INDEX 255

#define State_VERSION 1

enum DpeProfile
#ifdef __cplusplus
  : uint32_t
#endif // __cplusplus
 {
  DpeProfile_P256Sha256 = 3,
  DpeProfile_P384Sha384 = 4,
};
#ifndef __cplusplus
typedef uint32_t DpeProfile;
#endif // __cplusplus

/**
 * It is possible that there are multiple issues with the DPE state. At most one will be found.
 * There is no priority on which error will be found first if there are multiple.
 */
enum ValidationError
#ifdef __cplusplus
  : uint16_t
#endif // __cplusplus
 {
  ValidationError_MultipleNormalConnectedComponents = 0,
  ValidationError_CyclesInTree = 1,
  ValidationError_InactiveContextInvalidParent = 2,
  ValidationError_InactiveContextWithChildren = 3,
  ValidationError_BadContextState = 4,
  ValidationError_BadContextType = 5,
  ValidationError_InactiveContextWithMeasurement = 6,
  ValidationError_MixedContextLocality = 7,
  ValidationError_MultipleDefaultContexts = 8,
  ValidationError_SimulationNotSupported = 9,
  ValidationError_ParentDoesNotExist = 10,
  ValidationError_InternalDiceNotSupported = 11,
  ValidationError_InternalInfoNotSupported = 12,
  ValidationError_ChildDoesNotExist = 13,
  ValidationError_InactiveContextWithFlagSet = 14,
  ValidationError_LocalityMismatch = 15,
  ValidationError_DanglingRetiredContext = 16,
  ValidationError_MixedContextTypeConnectedComponents = 17,
  ValidationError_ChildWithMultipleParents = 18,
  ValidationError_ParentChildLinksCorrupted = 19,
  ValidationError_AllowCaNotSupported = 20,
  ValidationError_AllowX509NotSupported = 21,
  ValidationError_InactiveParent = 22,
  ValidationError_InactiveChild = 23,
  ValidationError_DpeNotMarkedInitialized = 24,
  ValidationError_InvalidMarker = 25,
  ValidationError_VersionMismatch = 26,
};
#ifndef __cplusplus
typedef uint16_t ValidationError;
#endif // __cplusplus

typedef struct CertifyKeyP256Resp CertifyKeyP256Resp;

typedef struct CertifyKeyP384Resp CertifyKeyP384Resp;

typedef struct CommandHdr {
  uint32_t magic;
  uint32_t cmd_id;
  uint32_t profile;
} CommandHdr;

typedef struct InitCtxCmd {
  uint32_t _0;
} InitCtxCmd;

typedef struct ContextHandle {
  uint8_t _0[SIZE];
} ContextHandle;
#define ContextHandle_SIZE 16

typedef uint8_t TciMeasurement[TCI_SIZE];

typedef struct DeriveContextFlags {
  uint32_t _0;
} DeriveContextFlags;

typedef struct DeriveContextCmd {
  struct ContextHandle handle;
  TciMeasurement data;
  struct DeriveContextFlags flags;
  uint32_t tci_type;
  uint32_t target_locality;
  uint32_t svn;
} DeriveContextCmd;

typedef struct CertifyKeyFlags {
  uint32_t _0;
} CertifyKeyFlags;

typedef struct CertifyKeyP256Cmd {
  struct ContextHandle handle;
  struct CertifyKeyFlags flags;
  uint32_t format;
  uint8_t label[32];
} CertifyKeyP256Cmd;

typedef struct CertifyKeyP384Cmd {
  struct ContextHandle handle;
  struct CertifyKeyFlags flags;
  uint32_t format;
  uint8_t label[48];
} CertifyKeyP384Cmd;

typedef struct SignFlags {
  uint32_t _0;
} SignFlags;

typedef struct SignP256Cmd {
  struct ContextHandle handle;
  uint8_t label[32];
  struct SignFlags flags;
  uint8_t digest[32];
} SignP256Cmd;

typedef struct SignP384Cmd {
  struct ContextHandle handle;
  uint8_t label[48];
  struct SignFlags flags;
  uint8_t digest[48];
} SignP384Cmd;

typedef struct DestroyCtxCmd {
  struct ContextHandle handle;
} DestroyCtxCmd;

typedef struct GetCertificateChainCmd {
  uint32_t offset;
  uint32_t size;
} GetCertificateChainCmd;

/**
 * ABI input structure for UpdateContextMeasurement.
 *
 * Wire layout (after CommandHdr):
 * | Offset    | Type       | Name              | Description                          |
 * |-----------|------------|-------------------|--------------------------------------|
 * | 0x00      | BYTES[16]  | parent_handle     | Handle of the parent context.        |
 * | 0x10      | HASH       | data              | New TCI measurement data.            |
 * | 0x10+H    | U32        | reserved          | Reserved; must be zero.              |
 * | 0x14+H    | U32        | tci_type          | INPUT_TYPE identifying the child.    |
 * | 0x18+H    | U32        | reserved_svn      | Reserved; ignored by this command.   |
 */
typedef struct UpdateContextMeasurementCmd {
  /**
   * Handle of the parent context. Must not be the default handle.
   */
  struct ContextHandle parent_handle;
  /**
   * New TCI measurement to extend into the child context.
   */
  TciMeasurement data;
  /**
   * Reserved bitfield; must be zero.
   */
  uint32_t reserved;
  /**
   * Identifies the direct child of parent_handle to update (matched by tci_type).
   */
  uint32_t tci_type;
  /**
   * Reserved for future use; ignored by this command. SVN is fixed at context creation
   * via DeriveContext and cannot be updated here.
   */
  uint32_t reserved_svn;
} UpdateContextMeasurementCmd;

typedef struct ResponseHdr {
  uint32_t magic;
  uint32_t status;
  DpeProfile profile;
} ResponseHdr;

typedef struct GetProfileResp {
  struct ResponseHdr resp_hdr;
  uint16_t major_version;
  uint16_t minor_version;
  uint32_t vendor_id;
  uint32_t vendor_sku;
  uint32_t max_tci_nodes;
  uint32_t flags;
} GetProfileResp;

typedef struct NewHandleResp {
  struct ResponseHdr resp_hdr;
  struct ContextHandle handle;
} NewHandleResp;

typedef struct DeriveContextResp {
  struct ResponseHdr resp_hdr;
  struct ContextHandle handle;
  struct ContextHandle parent_handle;
} DeriveContextResp;

/**
 * Response for the UpdateContextMeasurement vendor command.
 */
typedef struct UpdateContextMeasurementResp {
  struct ResponseHdr resp_hdr;
  /**
   * Rotated handle for the updated child context.
   */
  struct ContextHandle new_context_handle;
  /**
   * Rotated handle for the parent context (always retained).
   */
  struct ContextHandle new_parent_context_handle;
} UpdateContextMeasurementResp;

typedef struct DeriveContextExportedCdiResp {
  struct ResponseHdr resp_hdr;
  struct ContextHandle handle;
  struct ContextHandle parent_handle;
  uint8_t exported_cdi[MAX_EXPORTED_CDI_SIZE];
  uint32_t certificate_size;
  uint8_t new_certificate[MAX_CERT_SIZE];
} DeriveContextExportedCdiResp;

typedef struct SignP256Resp {
  struct ResponseHdr resp_hdr;
  struct ContextHandle new_context_handle;
  uint8_t sig_r[32];
  uint8_t sig_s[32];
} SignP256Resp;

typedef struct SignP384Resp {
  struct ResponseHdr resp_hdr;
  struct ContextHandle new_context_handle;
  uint8_t sig_r[48];
  uint8_t sig_s[48];
} SignP384Resp;

typedef struct GetCertificateChainResp {
  struct ResponseHdr resp_hdr;
  uint32_t certificate_size;
  uint8_t certificate_chain[MAX_CHUNK_SIZE];
} GetCertificateChainResp;

enum PlatformError_Tag
#ifdef __cplusplus
  : uint16_t
#endif // __cplusplus
 {
  PlatformError_CertificateChainError = 1,
  PlatformError_NotImplemented = 2,
  PlatformError_IssuerNameError = 3,
  PlatformError_PrintError = 4,
  PlatformError_SerialNumberError = 5,
  PlatformError_SubjectKeyIdentifierError = 6,
  PlatformError_CertValidityError = 7,
  PlatformError_IssuerKeyIdentifierError = 8,
  PlatformError_SubjectAlternativeNameError = 9,
  PlatformError_MissingUeidError = 10,
  PlatformError_InvalidUeidError = 11,
};
#ifndef __cplusplus
typedef uint16_t PlatformError_Tag;
#endif // __cplusplus

typedef union PlatformError {
  PlatformError_Tag tag;
  struct {
    PlatformError_Tag issuer_name_error_tag;
    uint32_t issuer_name_error;
  };
  struct {
    PlatformError_Tag print_error_tag;
    uint32_t print_error;
  };
  struct {
    PlatformError_Tag serial_number_error_tag;
    uint32_t serial_number_error;
  };
  struct {
    PlatformError_Tag subject_key_identifier_error_tag;
    uint32_t subject_key_identifier_error;
  };
  struct {
    PlatformError_Tag cert_validity_error_tag;
    uint32_t cert_validity_error;
  };
  struct {
    PlatformError_Tag issuer_key_identifier_error_tag;
    uint32_t issuer_key_identifier_error;
  };
  struct {
    PlatformError_Tag subject_alternative_name_error_tag;
    uint32_t subject_alternative_name_error;
  };
} PlatformError;

enum CryptoError_Tag
#ifdef __cplusplus
  : uint16_t
#endif // __cplusplus
 {
  CryptoError_AbstractionLayer = 1,
  CryptoError_CryptoLibError = 2,
  CryptoError_Size = 3,
  CryptoError_NotImplemented = 4,
  CryptoError_HashError = 5,
  CryptoError_InvalidExportedCdiHandle = 6,
  CryptoError_ExportedCdiHandleDuplicateCdi = 7,
  CryptoError_ExportedCdiHandleLimitExceeded = 8,
  CryptoError_MismatchedAlgorithm = 9,
};
#ifndef __cplusplus
typedef uint16_t CryptoError_Tag;
#endif // __cplusplus

typedef union CryptoError {
  CryptoError_Tag tag;
  struct {
    CryptoError_Tag abstraction_layer_tag;
    uint32_t abstraction_layer;
  };
  struct {
    CryptoError_Tag crypto_lib_error_tag;
    uint32_t crypto_lib_error;
  };
  struct {
    CryptoError_Tag hash_error_tag;
    uint32_t hash_error;
  };
} CryptoError;

enum DpeErrorCode_Tag
#ifdef __cplusplus
  : uint32_t
#endif // __cplusplus
 {
  DpeErrorCode_NoError = 0,
  DpeErrorCode_InternalError = 1,
  DpeErrorCode_InvalidCommand = 2,
  DpeErrorCode_InvalidArgument = 3,
  DpeErrorCode_ArgumentNotSupported = 4,
  DpeErrorCode_X509CsrUnset = 5,
  DpeErrorCode_X509InvalidState = 6,
  DpeErrorCode_X509SkipsExhausted = 7,
  DpeErrorCode_X509InvalidWidth = 8,
  DpeErrorCode_X509AlgorithmMismatch = 9,
  DpeErrorCode_InvalidHandle = 4096,
  DpeErrorCode_InvalidLocality = 4097,
  DpeErrorCode_MaxTcis = 4099,
  DpeErrorCode_InvalidMutRefBuf = 4100,
  DpeErrorCode_InvalidResponseBuf = 4101,
  DpeErrorCode_UninitializedResponseHeader = 4102,
  /**
   * Returned by UpdateContextMeasurement when PARENT_CONTEXT_HANDLE does not
   * exist in the caller's locality. Value matches the OCP iROT profile spec (0x85).
   */
  DpeErrorCode_InvalidParentLocality = 133,
  DpeErrorCode_Platform = 16777216,
  DpeErrorCode_Crypto = 33554432,
  DpeErrorCode_Validation = 50331648,
};
#ifndef __cplusplus
typedef uint32_t DpeErrorCode_Tag;
#endif // __cplusplus

typedef union DpeErrorCode {
  DpeErrorCode_Tag tag;
  struct {
    DpeErrorCode_Tag platform_tag;
    union PlatformError platform;
  };
  struct {
    DpeErrorCode_Tag crypto_tag;
    union CryptoError crypto;
  };
  struct {
    DpeErrorCode_Tag validation_tag;
    ValidationError validation;
  };
} DpeErrorCode;

#ifdef __cplusplus
} // extern "C"
#endif
