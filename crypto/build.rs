// Licensed under the Apache-2.0 license

fn main() {
    #[cfg(feature = "openssl")]
    {
        use {
            fs::File,
            openssl::{ec, nid, pkey},
            std::env,
            std::fs,
            std::io::Write,
            std::path::Path,
        };

        #[cfg(feature = "dpe_profile_p256_sha256")]
        const ALIAS_PRIV: &str = "../platform/src/test_data/key_256.pem";

        #[cfg(feature = "dpe_profile_p384_sha384")]
        const ALIAS_PRIV: &str = "../platform/src/test_data/key_384.pem";

        #[cfg(feature = "dpe_profile_p256_sha256")]
        const CURVE_ID: nid::Nid = nid::Nid::X9_62_PRIME256V1;

        #[cfg(feature = "dpe_profile_p384_sha384")]
        const CURVE_ID: nid::Nid = nid::Nid::SECP384R1;

        println!("cargo:rerun-if-changed={ALIAS_PRIV}");

        let out_dir = env::var_os("OUT_DIR").unwrap();

        let pem = if Path::new(ALIAS_PRIV).exists() {
            let input_pem = fs::read(ALIAS_PRIV).unwrap();
            let ec_priv: ec::EcKey<pkey::Private> =
                ec::EcKey::private_key_from_pem(&input_pem).unwrap();
            ec_priv.private_key_to_pem().unwrap()
        } else {
            let group = ec::EcGroup::from_curve_name(CURVE_ID).unwrap();
            let ec_key = ec::EcKey::generate(&group).unwrap();
            ec_key.private_key_to_pem().unwrap()
        };

        let path = Path::new(&out_dir).join("alias_priv.pem");
        let mut sample_alias_key_file = File::create(path).unwrap();
        sample_alias_key_file.write_all(&pem).unwrap();
    }
}
