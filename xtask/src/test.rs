// Licensed under the Apache-2.0 license

use std::process::Command;

pub enum CargoTestError {
    TestFailed,
    IOError(std::io::Error),
}

pub type CargoTestResult<T> = Result<T, CargoTestError>;

/// Cargo test case wrapper with all its configurations
#[derive(Debug, Clone)]
pub struct CargoTest {
    package: String,
    features: Vec<String>,
    default_features: bool,
}

impl CargoTest {
    pub fn from_package_name(package: String) -> Self {
        Self {
            package,
            features: vec![],
            default_features: false,
        }
    }

    pub fn add_feature(mut self, feature: String) -> Self {
        self.features.push(feature);
        self
    }

    #[allow(dead_code)]
    pub fn with_default_features(mut self, enabled: bool) -> Self {
        self.default_features = enabled;
        self
    }

    fn features(&self) -> String {
        let mut features = String::default();

        for feature in &self.features {
            features.push_str(feature);
            features.push(',')
        }

        if !self.features.is_empty() {
            features.truncate(features.len() - 1);
        }

        features
    }

    /// Run tests for the specified package with a set of features.
    pub fn run(&self) -> CargoTestResult<()> {
        let mut command_args = vec!["test", "-p", self.package.as_str()];

        let mut features = "--features=".to_string();
        features.push_str(self.features().as_str());
        command_args.push(features.as_str());

        if !self.default_features {
            command_args.push("--no-default-features");
        }

        let test_result = Command::new("cargo")
            .args(&command_args)
            .status()
            .map_err(CargoTestError::IOError)?;

        if !test_result.success() {
            return Err(CargoTestError::TestFailed);
        }

        Ok(())
    }
}

const DPE_PROFILES: &[&str] = &["p256", "p384", "ml-dsa", "hybrid"];
const TOOLS_PROFILES: &[&str] = &["p256", "p384", "ml-dsa"];

pub fn test_dpe() -> Vec<CargoTest> {
    let mut tests: Vec<CargoTest> = vec![];

    for profile in DPE_PROFILES {
        tests.push(
            CargoTest::from_package_name("caliptra-dpe".into())
                .add_feature(profile.to_string())
                .add_feature("cfi".into()),
        );
    }

    tests
}

pub fn test_crypto() -> Vec<CargoTest> {
    vec![CargoTest::from_package_name("caliptra-crypto-dpe".into())]
}

pub fn test_platform() -> Vec<CargoTest> {
    vec![CargoTest::from_package_name("caliptra-dpe-platform".into())]
}

pub fn test_tools_simulator() -> Vec<CargoTest> {
    let mut tests = vec![];

    for package in ["caliptra-dpe-tools", "caliptra-dpe-simulator"] {
        for profile in TOOLS_PROFILES {
            tests.push(
                CargoTest::from_package_name(package.into())
                    .add_feature(profile.to_string())
                    .add_feature("rustcrypto".to_string()),
            );
        }
    }

    tests
}

pub fn run_test_suite(tests: Vec<CargoTest>) {
    for test in tests {
        match test.run() {
            Err(CargoTestError::TestFailed) => {
                eprintln!("Test failed: {:?}", test.package);
            }
            Err(CargoTestError::IOError(e)) => {
                eprint!("Test I/O error: {:?}", e);
            }
            Ok(_) => {
                println!("Ok: {:?}", test.package);
            }
        }
    }
}
