// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Context, Result};
use caliptra_dpe_dice_asn1::{
    ExtensionDefinition, FwidWriter, GoldenDefinitions, GoldenKeyAlgorithm, GoldenProfile,
    TcbInfoWriter, Ueid,
};
use clap::Parser;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Parser)]
pub struct Args {
    /// Profiles to regenerate; all profiles when omitted
    profiles: Vec<GoldenProfile>,

    /// Compare generated artifacts with the checked-in files without writing
    #[arg(long)]
    check: bool,
}

struct ExtensionValues {
    ueid: Vec<u8>,
    multi_tcb_info: Vec<u8>,
}

struct GeneratedArtifacts {
    profile: &'static str,
    certificate_der: Vec<u8>,
    csr_der: Vec<u8>,
}

#[derive(asn1::Asn1Write)]
struct EcPrivateKey<'a> {
    version: u64,
    private_key: &'a [u8],
    #[explicit(0)]
    parameters: Option<asn1::ObjectIdentifier>,
}

pub fn run(args: &Args) -> Result<()> {
    let profiles: &[GoldenProfile] = if args.profiles.is_empty() {
        &GoldenProfile::ALL
    } else {
        args.profiles.as_slice()
    };

    check_openssl()?;

    // Complete every OpenSSL operation before touching a checked-in artifact.
    let artifacts = profiles
        .iter()
        .copied()
        .map(generate_profile)
        .collect::<Result<Vec<_>>>()?;

    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be directly below the repository root")
        .to_path_buf()
        .join("dpe/src/x509_testdata");
    for artifact in artifacts {
        install_or_check(&output_dir, &artifact, args.check)?;
    }
    Ok(())
}

fn generate_profile(profile: GoldenProfile) -> Result<GeneratedArtifacts> {
    let config: GoldenDefinitions = profile.into();
    println!("Generating {} goldens", config.artifact_suffix);
    let extensions = build_extensions(&config)?;
    let key = build_key(&config)?;
    let certificate_der = generate_req(&config, &key, &extensions, true)?;
    let csr_der = generate_req(&config, &key, &extensions, false)?;
    validate_der("x509", &certificate_der)?;
    validate_der("req", &csr_der)?;

    Ok(GeneratedArtifacts {
        profile: config.artifact_suffix,
        certificate_der,
        csr_der,
    })
}

fn build_extensions(config: &GoldenDefinitions) -> Result<ExtensionValues> {
    let ueid_value = vec![config.ueid_fill; config.hash_size];
    let ueid = asn1::write_single(&Ueid { ueid: &ueid_value })
        .map_err(|e| anyhow!("encoding UEID: {e:?}"))?;
    let fwid_digest = vec![config.fwid_digest_fill; config.hash_size];
    let hash_alg = asn1::ObjectIdentifier::from_string(config.hash_oid.dotted)
        .ok_or_else(|| anyhow!("invalid hash OID {}", config.hash_oid.dotted))?;
    let fwids = (0..config.fwids_per_tcb_info)
        .map(|_| FwidWriter {
            hash_alg: hash_alg.clone(),
            digest: &fwid_digest,
        })
        .collect::<Vec<_>>();
    let tcb_infos = (0..config.tcb_info_count)
        .map(|_| TcbInfoWriter {
            fwids: Some(asn1::SequenceOfWriter::new(fwids.as_slice())),
        })
        .collect::<Vec<_>>();
    let multi_tcb_info = asn1::write_single(&asn1::SequenceOfWriter::new(tcb_infos.as_slice()))
        .map_err(|e| anyhow!("encoding MultiTcbInfo: {e:?}"))?;
    Ok(ExtensionValues {
        ueid,
        multi_tcb_info,
    })
}

fn build_key(config: &GoldenDefinitions) -> Result<Vec<u8>> {
    match config.key_algorithm {
        GoldenKeyAlgorithm::Ecdsa {
            curve_oid,
            scalar_size,
        } => {
            let scalar = vec![config.deterministic_key_fill; scalar_size];
            let parameters = asn1::ObjectIdentifier::from_string(curve_oid.dotted)
                .ok_or_else(|| anyhow!("invalid curve OID {}", curve_oid.dotted))?;
            asn1::write_single(&EcPrivateKey {
                version: 1,
                private_key: &scalar,
                parameters: Some(parameters),
            })
            .map_err(|e| anyhow!("encoding deterministic EC private key: {e:?}"))
        }
        GoldenKeyAlgorithm::Mldsa87 { seed_size } => run_openssl(
            &[
                "genpkey",
                "-algorithm",
                "ML-DSA-87",
                "-provider",
                "default",
                "-pkeyopt",
                &format!(
                    "hexseed:{}",
                    format!("{:02x}", config.deterministic_key_fill).repeat(seed_size)
                ),
            ],
            None,
        ),
    }
}

fn critical_prefix(critical: bool) -> &'static str {
    if critical {
        "critical,"
    } else {
        ""
    }
}

fn openssl_der_extension(definition: ExtensionDefinition, value: &[u8]) -> String {
    format!(
        "{}={}DER:{}",
        definition.oid.dotted,
        critical_prefix(definition.critical),
        hex::encode(value)
    )
}

fn generate_req(
    config: &GoldenDefinitions,
    key: &[u8],
    extensions: &ExtensionValues,
    certificate: bool,
) -> Result<Vec<u8>> {
    let mut args = vec!["req", "-new"];
    if certificate {
        args.push("-x509");
    }
    // OpenSSL's `req -key` does not interpret `-` as stdin, unlike many of its
    // other input options. The xtask is supported on the repository's Unix/Nix
    // development environments, where /dev/stdin avoids an intermediate file.
    args.extend(["-key", "/dev/stdin", "-outform", "DER"]);
    if let GoldenKeyAlgorithm::Ecdsa { .. } = config.key_algorithm {
        args.extend(["-keyform", "DER"]);
        args.push(match config.profile {
            GoldenProfile::P256 => "-sha256",
            GoldenProfile::P384 => "-sha384",
            GoldenProfile::Mldsa87 => unreachable!("ML-DSA has no ECDSA digest argument"),
        });
    }
    let signature_option = match config.key_algorithm {
        GoldenKeyAlgorithm::Ecdsa { .. } => "nonce-type:1",
        GoldenKeyAlgorithm::Mldsa87 { .. } => "deterministic:1",
    };
    args.extend(["-sigopt", signature_option]);
    let subject = format!("/CN={}", config.subject_common_name);
    let csr_subject = format!(
        "/CN={}/serialNumber={}",
        config.subject_common_name, config.csr_subject_serial
    );
    args.extend(["-subj", if certificate { &subject } else { &csr_subject }]);
    let basic_constraints = format!(
        "basicConstraints={}CA:{}",
        critical_prefix(config.basic_constraints_critical),
        if config.is_ca { "TRUE" } else { "FALSE" }
    );
    let key_usage = format!(
        "keyUsage={}{}{}",
        critical_prefix(config.key_usage_critical),
        if config.digital_signature {
            "digitalSignature"
        } else {
            ""
        },
        if config.key_cert_sign {
            ",keyCertSign"
        } else {
            ""
        }
    );
    if certificate {
        args.extend([
            "-set_serial",
            config.certificate_serial,
            "-not_before",
            config.not_before,
            "-not_after",
            config.not_after,
            "-addext",
            "subjectKeyIdentifier=hash",
            "-addext",
            &basic_constraints,
            "-addext",
            &key_usage,
        ]);
    } else {
        args.extend(["-addext", &basic_constraints]);
    }
    let ueid = openssl_der_extension(config.ueid, &extensions.ueid);
    let tcb = openssl_der_extension(config.multi_tcb_info, &extensions.multi_tcb_info);
    args.extend(["-addext", &ueid, "-addext", &tcb]);
    run_openssl(&args, Some(key))
}

fn validate_der(command: &str, der: &[u8]) -> Result<()> {
    let mut args = vec![command, "-inform", "DER", "-noout"];
    if command == "req" {
        args.push("-verify");
    }
    run_openssl(&args, Some(der)).map(|_| ())
}

fn run_openssl(args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut command = Command::new("openssl");
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("running openssl {}", args.join(" ")))?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .context("opening OpenSSL stdin")?
            .write_all(input)?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "openssl {} failed:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn check_openssl() -> Result<()> {
    run_openssl(&["version"], None)
        .context("OpenSSL is required but could not be found. Please ensure it is installed and in your PATH.")
        .map(|_| ())
}

fn install_or_check(dir: &Path, artifacts: &GeneratedArtifacts, check: bool) -> Result<()> {
    let outputs = [
        (
            dir.join(format!("golden_cert_{}.der", artifacts.profile)),
            artifacts.certificate_der.as_slice(),
        ),
        (
            dir.join(format!("golden_csr_{}.der", artifacts.profile)),
            artifacts.csr_der.as_slice(),
        ),
    ];
    for (path, generated) in outputs {
        if check {
            let existing = fs::read(&path)
                .with_context(|| format!("reading checked-in {}", path.display()))?;
            if existing != generated {
                bail!("{} is not up to date", path.display());
            }
            println!("Up to date: {}", path.display());
        } else {
            fs::write(&path, generated).with_context(|| format!("writing {}", path.display()))?;
            println!("Wrote {}", path.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_der_matches_expected_shape() {
        let definitions: GoldenDefinitions = GoldenProfile::P256.into();
        let extensions = build_extensions(&definitions).unwrap();
        assert_eq!(&extensions.ueid[..4], &[0x30, 0x22, 0x04, 0x20]);
        assert_eq!(
            &extensions.multi_tcb_info[..6],
            &[0x30, 0x33, 0x30, 0x31, 0xa6, 0x2f]
        );
        let parsed = asn1::parse_single::<Ueid<'_>>(&extensions.ueid).unwrap();
        assert_eq!(parsed.ueid.len(), definitions.hash_size);
        assert!(parsed
            .ueid
            .iter()
            .all(|byte| *byte == definitions.ueid_fill));
    }
}
