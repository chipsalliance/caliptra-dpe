// Licensed under the Apache-2.0 license

#[cfg(feature = "rustcrypto")]
use std::{env, fs, ops::Deref, path::Path};

fn main() {
    #[cfg(feature = "rustcrypto")]
    {
        const ALIAS_PRIV_256: &str = "../platform/src/test_data/key_256.pem";
        const ALIAS_PRIV_384: &str = "../platform/src/test_data/key_384.pem";

        const ALIAS_PRIV_MLDSA_87: &str = "../platform/src/test_data/key_mldsa_87.pem";

        println!("cargo:rerun-if-changed={ALIAS_PRIV_256}");
        println!("cargo:rerun-if-changed={ALIAS_PRIV_384}");
        println!("cargo:rerun-if-changed={ALIAS_PRIV_MLDSA_87}");

        let (pem_256, pem_384) = {
            use {
                base64ct::LineEnding,
                ecdsa::SigningKey,
                p256::NistP256,
                p384::NistP384,
                rand::{rngs::StdRng, SeedableRng},
                sec1::{DecodeEcPrivateKey, EncodeEcPrivateKey},
            };
            #[cfg(feature = "ml-dsa")]
            use {
                ml_dsa::{KeyGen, KeyPair, MlDsa87},
                pkcs8::{
                    der::pem::LineEnding as Pkcs8LineEnding, DecodePrivateKey, EncodePrivateKey,
                },
            };

            // generate 256 bit private key in PEM format
            let pem_256 = if Path::new(ALIAS_PRIV_256).exists() {
                let ec_secret = SigningKey::<NistP256>::read_sec1_pem_file(ALIAS_PRIV_256).unwrap();
                ec_secret
                    .to_sec1_pem(LineEnding::default())
                    .unwrap()
                    .deref()
                    .as_bytes()
                    .to_vec()
            } else {
                let ec_secret = SigningKey::<NistP256>::random(&mut StdRng::from_entropy());
                ec_secret
                    .to_sec1_pem(LineEnding::default())
                    .unwrap()
                    .deref()
                    .as_bytes()
                    .to_vec()
            };

            // generate 384 bit private key in PEM format
            let pem_384 = if Path::new(ALIAS_PRIV_384).exists() {
                let ec_secret = SigningKey::<NistP384>::read_sec1_pem_file(ALIAS_PRIV_384).unwrap();
                ec_secret
                    .to_sec1_pem(LineEnding::default())
                    .unwrap()
                    .deref()
                    .as_bytes()
                    .to_vec()
            } else {
                let ec_secret = SigningKey::<NistP384>::random(&mut StdRng::from_entropy());
                ec_secret
                    .to_sec1_pem(LineEnding::default())
                    .unwrap()
                    .deref()
                    .as_bytes()
                    .to_vec()
            };

            #[cfg(feature = "ml-dsa")]
            {
                let path_ml_dsa = Path::new(&out_dir).join("alias_priv_mldsa_87.pem");
                let pem_ml_dsa = if Path::new(ALIAS_PRIV_MLDSA_87).exists() {
                    let pem = String::from_utf8(fs::read(ALIAS_PRIV_MLDSA_87).unwrap()).unwrap();
                    let ml_dsa_secret = KeyPair::<MlDsa87>::from_pkcs8_pem(&pem).unwrap();
                    ml_dsa_secret
                        .to_pkcs8_pem(Pkcs8LineEnding::default())
                        .unwrap()
                        .deref()
                        .as_bytes()
                        .to_vec()
                } else {
                    let ml_dsa_secret = MlDsa87::key_gen(&mut StdRng::from_entropy());
                    ml_dsa_secret
                        .to_pkcs8_pem(Pkcs8LineEnding::default())
                        .unwrap()
                        .deref()
                        .as_bytes()
                        .to_vec()
                };
                fs::write(&path_ml_dsa, pem_ml_dsa).unwrap();
            }

            (pem_256, pem_384)
        };

        let out_dir = env::var_os("OUT_DIR").unwrap();

        // write 256 bit private key to file
        let path_256 = Path::new(&out_dir).join("alias_priv_256.pem");
        fs::write(&path_256, pem_256).unwrap();

        // write 384 bit private key to file
        let path_384 = Path::new(&out_dir).join("alias_priv_384.pem");
        fs::write(&path_384, pem_384).unwrap();
    }
}
