// Licensed under the Apache-2.0 license

#![no_std]

macro_rules! include_artifacts {
    ($cert_pem:ident, $cert_der:ident, $key_pem:ident, $key_der:ident, $suffix:expr) => {
        pub const $cert_pem: &str = include_str!(concat!(
            env!("OUT_DIR"),
            "/test_data/cert_",
            $suffix,
            ".pem"
        ));
        pub const $cert_der: &[u8] = include_bytes!(concat!(
            env!("OUT_DIR"),
            "/test_data/cert_",
            $suffix,
            ".der"
        ));
        pub const $key_pem: &str =
            include_str!(concat!(env!("OUT_DIR"), "/test_data/key_", $suffix, ".pem"));
        pub const $key_der: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/test_data/key_", $suffix, ".der"));
    };
}

include_artifacts!(
    CERT_P256_PEM,
    CERT_P256_DER,
    KEY_P256_PEM,
    KEY_P256_DER,
    "p256"
);
include_artifacts!(
    CERT_P384_PEM,
    CERT_P384_DER,
    KEY_P384_PEM,
    KEY_P384_DER,
    "p384"
);
include_artifacts!(
    CERT_MLDSA_87_PEM,
    CERT_MLDSA_87_DER,
    KEY_MLDSA_87_PEM,
    KEY_MLDSA_87_DER,
    "mldsa_87"
);
