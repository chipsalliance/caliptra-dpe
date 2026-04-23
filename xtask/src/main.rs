// Licensed under the Apache-2.0 license

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::path::Path;
use std::process::Command;

// TODO(clundin): Support "hybrid"
const PROFILES: &[&str] = &["ml-dsa", "p256", "p384"];
const MANIFESTS: &[&str] = &[
    "crypto/Cargo.toml",
    "platform/Cargo.toml",
    "dpe/Cargo.toml",
    "simulator/Cargo.toml",
    "tools/Cargo.toml",
];

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all CI checks
    Ci,
    /// Run tests
    Test(TestArgs),
    /// Run formatting, linters and header checks
    Precheckin(PrecheckinArgs),
    /// Run a tool from the tools/ folder
    RunTool(RunToolArgs),
}

#[derive(Parser)]
pub struct TestArgs {
    #[command(subcommand)]
    pub command: Option<TestSubcommands>,
}

#[derive(Subcommand)]
pub enum TestSubcommands {
    /// Run Rust unit tests
    Unit,
    /// Run Go verification tests
    Verification,
    /// Run cert parser tests
    Certs,
    /// Run Miri tests
    Miri(MiriArgs),
}

#[derive(Parser)]
pub struct PrecheckinArgs {
    #[command(subcommand)]
    pub command: Option<PrecheckinSubcommands>,
}

#[derive(Subcommand)]
pub enum PrecheckinSubcommands {
    /// Check file headers
    Headers,
    /// Check formatting (Rust and Go)
    Format,
    /// Run linters (Clippy and Golint)
    Lint,
}

#[derive(Parser)]
pub struct RunToolArgs {
    #[command(subcommand)]
    pub tool: ToolSubcommands,
}

#[derive(Subcommand)]
pub enum ToolSubcommands {
    /// Run sample_dpe_cert
    SampleDpeCert {
        #[arg(long, default_value = "ml-dsa")]
        profile: String,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Run cert-size
    CertSize {
        #[arg(long, default_value = "ml-dsa")]
        profile: String,
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[derive(Parser)]
pub struct MiriArgs {
    #[arg(long, default_value_t = false)]
    nextest: bool,

    #[arg(long, default_value_t = 1)]
    nthreads: u32,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Ci => run_ci()?,
        Commands::Test(args) => run_test_command(args)?,
        Commands::Precheckin(args) => run_precheckin_command(args)?,
        Commands::RunTool(args) => run_tool_command(args)?,
    }

    Ok(())
}

fn run_ci() -> Result<()> {
    run_precheckin()?;
    run_tests()?;

    // Additional checks for specific binaries/tools
    cargo_run(
        &CargoOptions::with_features("tools/Cargo.toml", "hybrid"),
        &["--bin", "cert-size", "--"],
    )?;
    cargo_clippy(&CargoOptions::with_features_bin(
        "tools/Cargo.toml",
        "hybrid",
        "cert-size",
    ))?;

    // Build fuzz target
    run_fuzz_checks()?;

    Ok(())
}

fn run_precheckin_command(args: &PrecheckinArgs) -> Result<()> {
    match &args.command {
        Some(PrecheckinSubcommands::Headers) => fix_headers(true)?,
        Some(PrecheckinSubcommands::Format) => run_format()?,
        Some(PrecheckinSubcommands::Lint) => run_lint()?,
        None => run_precheckin()?,
    }
    Ok(())
}

fn run_precheckin() -> Result<()> {
    fix_headers(true)?;
    run_format()?;
    run_lint()?;
    Ok(())
}

fn run_format() -> Result<()> {
    format_rust_targets()?;
    format_go_targets()?;
    Ok(())
}

fn run_lint() -> Result<()> {
    for profile in PROFILES {
        lint_rust_targets(profile)?;
    }
    Ok(())
}

fn run_test_command(args: &TestArgs) -> Result<()> {
    match &args.command {
        Some(TestSubcommands::Unit) => run_unit_tests()?,
        Some(TestSubcommands::Verification) => run_verification_tests()?,
        Some(TestSubcommands::Certs) => run_cert_parser_tests()?,
        Some(TestSubcommands::Miri(args)) => run_miri_tests(args)?,
        None => run_tests()?,
    }
    Ok(())
}

fn run_tests() -> Result<()> {
    run_unit_tests()?;
    run_verification_tests()?;
    run_cert_parser_tests()?;
    Ok(())
}

fn run_tool_command(args: &RunToolArgs) -> Result<()> {
    match &args.tool {
        ToolSubcommands::SampleDpeCert { profile, args } => {
            let mut cargo_args = vec!["--bin", "sample_dpe_cert", "--"];
            cargo_args.extend(args.iter().map(|s| s.as_str()));
            cargo_run(
                &CargoOptions::with_features("tools/Cargo.toml", profile),
                &cargo_args,
            )?;
        }
        ToolSubcommands::CertSize { profile, args } => {
            let mut cargo_args = vec!["--bin", "cert-size", "--"];
            cargo_args.extend(args.iter().map(|s| s.as_str()));
            cargo_run(
                &CargoOptions::with_features("tools/Cargo.toml", profile),
                &cargo_args,
            )?;
        }
    }
    Ok(())
}

fn run_unit_tests() -> Result<()> {
    for profile in PROFILES {
        build_rust_targets(profile)?;
        test_rust_targets(profile)?;
    }
    Ok(())
}

fn run_verification_tests() -> Result<()> {
    for profile in PROFILES {
        run_verification_test(profile, "rustcrypto")?;
    }
    Ok(())
}

fn run_cert_parser_tests() -> Result<()> {
    for profile in PROFILES {
        run_cert_parser_test(profile)?;
    }
    Ok(())
}

fn run_miri_tests(args: &MiriArgs) -> Result<()> {
    for profile in PROFILES {
        run_miri_test(profile, args)?
    }
    Ok(())
}

fn fix_headers(check: bool) -> Result<()> {
    println!("Running file-header-fix");
    cargo()
        .args([
            "install",
            "--git",
            "https://github.com/chipsalliance/caliptra-sw",
            "--root",
            "/tmp/caliptra-file-header-fix",
            "caliptra-file-header-fix",
        ])
        .run()?;

    let mut fix_cmd = Cmd::new("/tmp/caliptra-file-header-fix/bin/caliptra-file-header-fix");
    if check {
        fix_cmd = fix_cmd.arg("--check");
    }
    fix_cmd.run()?;
    Ok(())
}

fn run_cert_parser_test(profile: &str) -> Result<()> {
    println!("Running cert parser tests for profile: {}", profile);
    let script_dir = Path::new("verification/cert_parser");

    Cmd::new("uv")
        .args(["venv", "--clear"])
        .dir(script_dir)
        .run()?;
    Cmd::new("uv")
        .args([
            "pip",
            "install",
            "-e",
            ".",
            "--index-url",
            "https://pypi.org/simple",
        ])
        .dir(script_dir)
        .run()?;

    Cmd::new(".venv/bin/pytest")
        .dir(script_dir)
        .env("DPE_PROFILE", profile)
        .run()?;
    Ok(())
}

fn features_for(manifest: &str, profile: &str) -> Option<String> {
    match manifest {
        "dpe/Cargo.toml" => Some(format!("{},cfi", profile)),
        "simulator/Cargo.toml" => Some(format!("{},rustcrypto", profile)),
        "tools/Cargo.toml" => Some(profile.to_string()),
        _ => None,
    }
}

fn build_rust_targets(profile: &str) -> Result<()> {
    for manifest in MANIFESTS {
        cargo_build(&CargoOptions::with_features(
            manifest,
            &features_for(manifest, profile).unwrap_or_default(),
        ))?;
    }
    Ok(())
}

fn lint_rust_targets(profile: &str) -> Result<()> {
    for manifest in MANIFESTS {
        cargo_clippy(&CargoOptions::with_features(
            manifest,
            &features_for(manifest, profile).unwrap_or_default(),
        ))?;
    }
    Ok(())
}

fn format_rust_targets() -> Result<()> {
    for manifest in MANIFESTS {
        cargo()
            .args(["fmt", "--manifest-path", manifest, "--check"])
            .run()?;
    }
    Ok(())
}

fn format_go_targets() -> Result<()> {
    let verification_dir = Path::new("verification");
    let output = Cmd::new("gofmt")
        .args(["-l", "."])
        .dir(verification_dir)
        .output()?;
    if !output.stdout.is_empty() {
        return Err(anyhow!("Go files are not formatted. Please run gofmt -w ."));
    }

    let output = Cmd::new("golint").dir(verification_dir).output()?;
    if !output.stdout.is_empty() {
        return Err(anyhow!("Go files have lint errors."));
    }
    Ok(())
}

fn test_rust_targets(profile: &str) -> Result<()> {
    for manifest in MANIFESTS {
        match *manifest {
            "dpe/Cargo.toml" => {
                let opts = CargoOptions::with_features(manifest, &format!("{},cfi", profile));
                cargo_test(&opts, &["--test-threads=1"])?;
            }
            "tools/Cargo.toml" => {} // tools has no tests
            m => {
                let opts =
                    CargoOptions::with_features(m, &features_for(m, profile).unwrap_or_default());
                cargo_test(&opts, &[])?;
            }
        }
    }
    Ok(())
}

fn run_miri_target(profile: &str, args: &MiriArgs) -> Result<()> {
    // Note: CFI feature is excluded because it uses inline assembly which Miri does not support
    let opts = CargoOptions::with_features("dpe/Cargo.toml", profile);
    cargo_miri(&opts, None, args)?;
    Ok(())
}

fn cargo_miri(
    opts: &CargoOptions,
    extra_args: Option<&[&str]>,
    miri_args: &MiriArgs,
) -> Result<()> {
    let mut cmd = match miri_args.nextest {
        true => cargo().args(["miri", "nextest", "run"]),
        false => cargo().args(["miri", "test"]),
    };

    cmd = cmd.args(["--manifest-path", opts.manifest_path]);
    if !opts.features.is_empty() {
        cmd = cmd.arg(format!("--features={}", opts.features));
    }

    cmd = cmd.arg("--no-default-features");
    if let Some(extra_args) = extra_args {
        cmd = cmd.arg("--").args(extra_args);
        if !miri_args.nextest {
            cmd = cmd.arg(format!("--test-threads={}", miri_args.nthreads).as_str())
        }
    }

    cmd.run()
}

fn run_verification_test(profile: &str, crypto: &str) -> Result<()> {
    let features = if profile == "hybrid" {
        format!("p384,ml-dsa,{}", crypto)
    } else {
        format!("{},{}", profile, crypto)
    };
    cargo_build(&CargoOptions::with_features(
        "simulator/Cargo.toml",
        &features,
    ))?;
    Cmd::new("go")
        .args(["test", "-v"])
        .dir("verification/testing")
        .run()?;
    Ok(())
}

/// Requires the same setup as the regular unit tests for profiles and feature flags.
/// Since miri tests are computaional expenseive, use nextest to speed things up.
fn run_miri_test(profile: &str, args: &MiriArgs) -> Result<()> {
    run_miri_target(profile, args)?;
    Ok(())
}

fn run_fuzz_checks() -> Result<()> {
    let fuzz_dir = Path::new("dpe/fuzz");
    let nightly = "nightly-2025-07-08";
    cargo()
        .args([
            &format!("+{}", nightly),
            "install",
            "cargo-fuzz",
            "cargo-afl",
            "--locked",
        ])
        .run()?;
    cargo().args(["fmt", "--check"]).dir(fuzz_dir).run()?;
    cargo()
        .args(["clippy", "--features", "libfuzzer-sys"])
        .dir(fuzz_dir)
        .run()?;
    cargo()
        .args(["clippy", "--features", "afl"])
        .dir(fuzz_dir)
        .run()?;
    cargo()
        .args([
            &format!("+{}", nightly),
            "fuzz",
            "build",
            "--features",
            "libfuzzer-sys",
        ])
        .dir(fuzz_dir)
        .run()?;
    cargo()
        .args([
            &format!("+{}", nightly),
            "afl",
            "build",
            "--features",
            "afl",
        ])
        .dir(fuzz_dir)
        .run()?;
    Ok(())
}

struct Cmd(Command);

impl Cmd {
    fn new(exe: &str) -> Self {
        Self(Command::new(exe))
    }
    fn arg(mut self, arg: impl AsRef<std::ffi::OsStr>) -> Self {
        self.0.arg(arg);
        self
    }
    fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.0.args(args);
        self
    }
    fn dir(mut self, path: impl AsRef<Path>) -> Self {
        self.0.current_dir(path);
        self
    }
    fn env(mut self, key: impl AsRef<std::ffi::OsStr>, val: impl AsRef<std::ffi::OsStr>) -> Self {
        self.0.env(key, val);
        self
    }
    fn run(mut self) -> Result<()> {
        if self.0.status()?.success() {
            Ok(())
        } else {
            Err(anyhow!("Command failed: {:?}", self.0))
        }
    }
    fn output(mut self) -> Result<std::process::Output> {
        self.0
            .output()
            .map_err(|e| anyhow!("Failed to execute {:?}: {}", self.0, e))
    }
}

fn cargo() -> Cmd {
    Cmd::new("cargo")
}

pub struct CargoOptions<'a> {
    pub manifest_path: &'a str,
    pub features: String,
    pub bin: Option<&'a str>,
}

impl<'a> CargoOptions<'a> {
    fn with_features(manifest_path: &'a str, features: &str) -> Self {
        Self {
            manifest_path,
            features: features.to_string(),
            bin: None,
        }
    }
    fn with_features_bin(manifest_path: &'a str, features: &str, bin: &'a str) -> Self {
        Self {
            manifest_path,
            features: features.to_string(),
            bin: Some(bin),
        }
    }
}

fn cargo_build(opts: &CargoOptions) -> Result<()> {
    let mut cmd = cargo().args(["build", "--manifest-path", opts.manifest_path]);
    if !opts.features.is_empty() {
        cmd = cmd.arg(format!("--features={}", opts.features));
    }
    cmd.arg("--no-default-features").run()
}

fn cargo_test(opts: &CargoOptions, extra_args: &[&str]) -> Result<()> {
    let mut cmd = cargo().args(["test", "--manifest-path", opts.manifest_path]);
    if !opts.features.is_empty() {
        cmd = cmd.arg(format!("--features={}", opts.features));
    }
    cmd = cmd.arg("--no-default-features");
    if !extra_args.is_empty() {
        cmd = cmd.arg("--").args(extra_args);
    }
    cmd.run()
}

fn cargo_clippy(opts: &CargoOptions) -> Result<()> {
    let mut cmd = cargo().args(["clippy", "--manifest-path", opts.manifest_path]);
    if let Some(bin) = opts.bin {
        cmd = cmd.arg("--bin").arg(bin);
    }
    if !opts.features.is_empty() {
        cmd = cmd.arg(format!("--features={}", opts.features));
    }
    cmd.args(["--no-default-features", "--", "--deny=warnings"])
        .run()
}

fn cargo_run(opts: &CargoOptions, extra_args: &[&str]) -> Result<()> {
    let mut cmd = cargo().args(["run", "--manifest-path", opts.manifest_path]);
    if !opts.features.is_empty() {
        cmd = cmd.arg(format!("--features={}", opts.features));
    }
    cmd = cmd.arg("--no-default-features");
    cmd.args(extra_args).run()
}
