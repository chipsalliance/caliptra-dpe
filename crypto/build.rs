// Licensed under the Apache-2.0 license

use {
    openssl::{ec, nid, pkey},
    fs::File,
    std::fs,
    std::io::Write,
    std::path::Path,
    std::env,
};

fn main() {
    const ALIAS_PRIV: &str = "data/alias_priv.pem";
    println!("cargo:rerun-if-changed={ALIAS_PRIV}");

    let out_dir = env::var_os("OUT_DIR").unwrap();

    let pem = if Path::new(ALIAS_PRIV).exists() {
        let input_pem = fs::read(ALIAS_PRIV).unwrap();
        let ec_priv: ec::EcKey<pkey::Private> = ec::EcKey::private_key_from_pem(&input_pem).unwrap();
        ec_priv.private_key_to_pem().unwrap()
    } else {
        let group = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = ec::EcKey::generate(&group).unwrap();
        ec_key.private_key_to_pem().unwrap()
    };

    let path = Path::new(&out_dir).join("alias_priv.pem");
    let mut sample_alias_key_file = File::create(path).unwrap();
    sample_alias_key_file.write_all(&pem).unwrap();
}

