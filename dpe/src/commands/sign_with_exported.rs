// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response, ResponseHdr, SignWithExportedResp},
    DPE_PROFILE, MAX_EXPORTED_CDI_SIZE,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use crypto::{Crypto, Digest, EcdsaSig};

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct SignWithExportedFlags(u32);

bitflags! {
    impl SignWithExportedFlags: u32 {}
}

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct SignWithExportedCmd {
    pub flags: SignWithExportedFlags,
    pub exported_cdi: [u8; MAX_EXPORTED_CDI_SIZE],
    pub digest: [u8; DPE_PROFILE.get_hash_size()],
}

impl SignWithExportedCmd {
    /// SignWithExported signs a `digest` using an ECDSA keypair derived from a exported_cdi
    /// handle and the CDI stored in DPE.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `digest` - The data to be signed
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn ecdsa_sign(
        &self,
        env: &mut DpeEnv<impl DpeTypes>,
        digest: &Digest,
    ) -> Result<EcdsaSig, DpeErrorCode> {
        let algs = DPE_PROFILE.alg_len();
        let cdi = env
            .crypto
            .get_exported_cdi()
            .map_err(DpeErrorCode::Crypto)?;

        let key_label = b"Exported ECC";

        let key_pair =
            env.crypto
                .derive_key_pair_exported(algs, &cdi, key_label, &self.exported_cdi);
        if cfi_launder(key_pair.is_ok()) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_ok());
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_err());
        }
        let (priv_key, pub_key) = key_pair?;

        let sig = env
            .crypto
            .ecdsa_sign_with_derived(algs, digest, &priv_key, &pub_key)?;

        Ok(sig)
    }
}

impl CommandExecution for SignWithExportedCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        _dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        _locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        let digest = Digest::new(&self.digest)?;
        let EcdsaSig { r, s } = self.ecdsa_sign(env, &digest)?;

        let sig_r: [u8; DPE_PROFILE.get_ecc_int_size()] = r
            .bytes()
            .try_into()
            .map_err(|_| DpeErrorCode::InternalError)?;

        let sig_s: [u8; DPE_PROFILE.get_ecc_int_size()] = s
            .bytes()
            .try_into()
            .map_err(|_| DpeErrorCode::InternalError)?;

        Ok(Response::SignWithExported(SignWithExportedResp {
            sig_r,
            sig_s,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{tests::TEST_DIGEST, Command, CommandHdr, DeriveContextCmd, DeriveContextFlags},
        context::ContextHandle,
        dpe_instance::tests::{TestTypes, TEST_LOCALITIES},
        support::Support,
        MAX_EXPORTED_CDI_SIZE,
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::OpensslCrypto;
    use openssl::{bn::BigNum, ecdsa::EcdsaSig, x509::X509};
    use platform::default::DefaultPlatform;
    use zerocopy::IntoBytes;

    const TEST_SIGN_WITH_EXPORTED_CMD: SignWithExportedCmd = SignWithExportedCmd {
        exported_cdi: [0xA; MAX_EXPORTED_CDI_SIZE],
        flags: SignWithExportedFlags::empty(),
        digest: TEST_DIGEST,
    };

    #[test]
    fn test_deserialize_sign_with_exported() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new_for_test(Command::SIGN_WITH_EXPORTED)
            .as_bytes()
            .to_vec();
        command.extend(TEST_SIGN_WITH_EXPORTED_CMD.as_bytes());
        assert_eq!(
            Ok(Command::SignWithExported(&TEST_SIGN_WITH_EXPORTED_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_sign_with_exported() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT | Support::CDI_EXPORT | Support::X509,
        )
        .unwrap();

        let resp = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_hash_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::EXPORT_CDI
                | DeriveContextFlags::CREATE_CERTIFICATE,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let resp = match resp {
            Response::DeriveContext(resp) => resp,
            _ => panic!("unexpected response type from DeriveContextCmd"),
        };

        let sig = {
            let cmd = SignWithExportedCmd {
                exported_cdi: resp.exported_cdi,
                flags: SignWithExportedFlags::empty(),
                digest: TEST_DIGEST,
            };
            let resp = match cmd.execute(&mut dpe, &mut env, TEST_LOCALITIES[0]).unwrap() {
                Response::SignWithExported(resp) => resp,
                _ => panic!("Incorrect response type"),
            };

            EcdsaSig::from_private_components(
                BigNum::from_slice(&resp.sig_r).unwrap(),
                BigNum::from_slice(&resp.sig_s).unwrap(),
            )
            .unwrap()
        };

        let x509 =
            X509::from_der(&resp.new_certificate[..resp.certificate_size.try_into().unwrap()])
                .unwrap();
        let ec_pub_key = x509.public_key().unwrap().ec_key().unwrap();
        assert!(sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap());
    }
}
