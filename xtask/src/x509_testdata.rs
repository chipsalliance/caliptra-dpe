// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Context, Result};
use caliptra_dpe_dice_asn1::{FwidWriter, TcbInfoWriter, Ueid};
use clap::{Parser, ValueEnum};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SUBJECT: &str = "/CN=DPE Leaf";
const CSR_SUBJECT: &str = "/CN=DPE Leaf/serialNumber=0000";
const NOT_BEFORE: &str = "20230227000000Z";
const NOT_AFTER: &str = "99991231235959Z";

#[derive(Parser)]
pub struct Args {
    /// Profiles to regenerate; all profiles when omitted
    #[arg(value_enum)]
    profiles: Vec<Profile>,

    /// Compare generated artifacts with the checked-in files without writing
    #[arg(long)]
    check: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Profile {
    P256,
    P384,
    Mldsa87,
}

#[derive(Clone, Copy)]
enum KeyConfig {
    Ecdsa {
        curve_oid: &'static str,
        scalar_size: usize,
        digest_arg: &'static str,
    },
    MlDsa87,
}

struct ProfileConfig {
    suffix: &'static str,
    hash_size: usize,
    hash_oid: &'static str,
    key: KeyConfig,
    signature_option: &'static str,
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
    let profiles = if args.profiles.is_empty() {
        vec![Profile::P256, Profile::P384, Profile::Mldsa87]
    } else {
        args.profiles.clone()
    };

    check_openssl()?;

    // Complete every OpenSSL operation before touching a checked-in artifact.
    let artifacts = profiles
        .into_iter()
        .map(generate_profile)
        .collect::<Result<Vec<_>>>()?;

    let output_dir = repository_root().join("dpe/src/x509_testdata");
    for artifact in artifacts {
        install_or_check(&output_dir, &artifact, args.check)?;
    }
    Ok(())
}

fn config(profile: Profile) -> ProfileConfig {
    match profile {
        Profile::P256 => ProfileConfig {
            suffix: "p256",
            hash_size: 32,
            hash_oid: "2.16.840.1.101.3.4.2.1",
            key: KeyConfig::Ecdsa {
                curve_oid: "1.2.840.10045.3.1.7",
                scalar_size: 32,
                digest_arg: "-sha256",
            },
            signature_option: "nonce-type:1",
        },
        Profile::P384 => ProfileConfig {
            suffix: "p384",
            hash_size: 48,
            hash_oid: "2.16.840.1.101.3.4.2.2",
            key: KeyConfig::Ecdsa {
                curve_oid: "1.3.132.0.34",
                scalar_size: 48,
                digest_arg: "-sha384",
            },
            signature_option: "nonce-type:1",
        },
        Profile::Mldsa87 => ProfileConfig {
            suffix: "mldsa87",
            hash_size: 48,
            hash_oid: "2.16.840.1.101.3.4.2.2",
            key: KeyConfig::MlDsa87,
            signature_option: "deterministic:1",
        },
    }
}

fn generate_profile(profile: Profile) -> Result<GeneratedArtifacts> {
    let config = config(profile);
    println!("Generating {} goldens", config.suffix);
    let extensions = build_extensions(&config)?;
    let key = build_key(&config)?;
    let certificate_der = generate_req(&config, &key, &extensions, true)?;
    let csr_der = generate_req(&config, &key, &extensions, false)?;
    validate_der("x509", &certificate_der)?;
    validate_der("req", &csr_der)?;

    Ok(GeneratedArtifacts {
        profile: config.suffix,
        certificate_der,
        csr_der,
    })
}

fn build_extensions(config: &ProfileConfig) -> Result<ExtensionValues> {
    let zeros = vec![0; config.hash_size];
    let ueid =
        asn1::write_single(&Ueid { ueid: &zeros }).map_err(|e| anyhow!("encoding UEID: {e:?}"))?;
    let hash_alg = asn1::ObjectIdentifier::from_string(config.hash_oid)
        .ok_or_else(|| anyhow!("invalid hash OID {}", config.hash_oid))?;
    let fwids = [FwidWriter {
        hash_alg,
        digest: &zeros,
    }];
    let tcb_infos = [TcbInfoWriter {
        fwids: Some(asn1::SequenceOfWriter::new(&fwids)),
    }];
    let multi_tcb_info = asn1::write_single(&asn1::SequenceOfWriter::new(&tcb_infos[..]))
        .map_err(|e| anyhow!("encoding MultiTcbInfo: {e:?}"))?;
    Ok(ExtensionValues {
        ueid,
        multi_tcb_info,
    })
}

fn build_key(config: &ProfileConfig) -> Result<Vec<u8>> {
    match config.key {
        KeyConfig::Ecdsa {
            curve_oid,
            scalar_size,
            ..
        } => {
            let scalar = vec![0x11; scalar_size];
            let parameters = asn1::ObjectIdentifier::from_string(curve_oid)
                .ok_or_else(|| anyhow!("invalid curve OID {curve_oid}"))?;
            asn1::write_single(&EcPrivateKey {
                version: 1,
                private_key: &scalar,
                parameters: Some(parameters),
            })
            .map_err(|e| anyhow!("encoding deterministic EC private key: {e:?}"))
        }
        KeyConfig::MlDsa87 => run_openssl(
            &[
                "genpkey",
                "-algorithm",
                "ML-DSA-87",
                "-provider",
                "default",
                "-pkeyopt",
                &format!("hexseed:{}", "11".repeat(32)),
            ],
            None,
        ),
    }
}

fn generate_req(
    config: &ProfileConfig,
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
    if matches!(config.key, KeyConfig::Ecdsa { .. }) {
        args.extend(["-keyform", "DER"]);
    }
    if let KeyConfig::Ecdsa { digest_arg, .. } = config.key {
        args.push(digest_arg);
    }
    args.extend(["-sigopt", config.signature_option]);
    args.extend(["-subj", if certificate { SUBJECT } else { CSR_SUBJECT }]);
    if certificate {
        args.extend([
            "-set_serial",
            "0",
            "-not_before",
            NOT_BEFORE,
            "-not_after",
            NOT_AFTER,
            "-addext",
            "subjectKeyIdentifier=hash",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature",
        ]);
    } else {
        args.extend(["-addext", "basicConstraints=critical,CA:FALSE"]);
    }
    let ueid = format!("2.23.133.5.4.4=critical,DER:{}", hex(&extensions.ueid));
    let tcb = format!("2.23.133.5.4.5=DER:{}", hex(&extensions.multi_tcb_info));
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
    run_openssl(&["version"], None).map(|_| ())
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

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be directly below the repository root")
        .to_path_buf()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_der_matches_expected_shape() {
        let extensions = build_extensions(&config(Profile::P256)).unwrap();
        assert_eq!(&extensions.ueid[..4], &[0x30, 0x22, 0x04, 0x20]);
        assert_eq!(
            &extensions.multi_tcb_info[..6],
            &[0x30, 0x33, 0x30, 0x31, 0xa6, 0x2f]
        );
        let parsed = asn1::parse_single::<Ueid<'_>>(&extensions.ueid).unwrap();
        assert_eq!(parsed.ueid, &[0; 32]);
    }
}
