// Licensed under the Apache-2.0 license

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

struct Algorithm {
    suffix: &'static str,
    gen_args: &'static [&'static str],
    pkey_args: &'static [&'static str],
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("test_data");
    fs::create_dir_all(&dest_path).unwrap();

    let openssl = |args: Vec<String>| {
        let status = Command::new("openssl")
            .args(&args)
            .current_dir(&dest_path)
            .status()
            .expect("failed to execute openssl");
        if !status.success() {
            panic!("openssl command failed: {:?}", args);
        }
    };

    let algorithms = [
        Algorithm {
            suffix: "p256",
            gen_args: &["ecparam", "-name", "prime256v1", "-genkey", "-noout"],
            pkey_args: &["ec"],
        },
        Algorithm {
            suffix: "p384",
            gen_args: &["ecparam", "-name", "secp384r1", "-genkey", "-noout"],
            pkey_args: &["ec"],
        },
        Algorithm {
            suffix: "mldsa_87",
            gen_args: &[
                "genpkey",
                "-algorithm",
                "ML-DSA-87",
                "-provparam",
                "ml-dsa.output_formats=seed-only",
            ],
            pkey_args: &["pkey", "-provparam", "ml-dsa.output_formats=seed-only"],
        },
    ];

    for alg in algorithms {
        let key_pem = format!("key_{}.pem", alg.suffix);
        let cert_pem = format!("cert_{}.pem", alg.suffix);
        let key_der = format!("key_{}.der", alg.suffix);
        let cert_der = format!("cert_{}.der", alg.suffix);

        // Generate private key
        let mut gen_cmd = alg
            .gen_args
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        gen_cmd.extend(["-out".to_string(), key_pem.clone()]);
        openssl(gen_cmd);

        // Generate self-signed certificate
        openssl(vec![
            "req".to_string(),
            "-new".to_string(),
            "-key".to_string(),
            key_pem.clone(),
            "-x509".to_string(),
            "-nodes".to_string(),
            "-days".to_string(),
            "365000".to_string(),
            "-out".to_string(),
            cert_pem,
            "-addext".to_string(),
            "keyUsage=critical,keyCertSign".to_string(),
            "-subj".to_string(),
            "/CN=DPE Test Alias/".to_string(),
        ]);

        // Convert key to DER
        let mut pkey_cmd = alg
            .pkey_args
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        pkey_cmd.extend([
            "-in".to_string(),
            key_pem,
            "-outform".to_string(),
            "DER".to_string(),
            "-out".to_string(),
            key_der,
        ]);
        openssl(pkey_cmd);

        // Convert cert to DER
        openssl(vec![
            "x509".to_string(),
            "-in".to_string(),
            cert_der.replace(".der", ".pem"),
            "-outform".to_string(),
            "DER".to_string(),
            "-out".to_string(),
            cert_der,
        ]);
    }

    println!("cargo:rerun-if-changed=build.rs");
}
