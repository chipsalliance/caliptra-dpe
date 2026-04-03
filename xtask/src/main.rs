// Licensed under the Apache-2.0 license
use clap::{Parser, Subcommand};

mod test;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Xtask {
    #[command(subcommand)]
    xtask: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Test,
}

fn main() {
    let cli = Xtask::parse();
    match &cli.xtask {
        Commands::Test => {
            let tests = [
                test::test_crypto(),
                test::test_dpe(),
                test::test_tools_simulator(),
                test::test_platform(),
            ]
            .concat();

            test::run_test_suite(tests);
        }
    };
}
