// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ContextHandle, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response, ResponseHdr, SignResp},
    DPE_PROFILE,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_assert_ne};
use cfg_if::cfg_if;
use crypto::{Crypto, Digest, EcdsaSig};
#[cfg(not(feature = "disable_is_symmetric"))]
use crypto::{CryptoBuf, HmacSig};

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
pub struct SignFlags(u32);

bitflags! {
    impl SignFlags: u32 {
        const IS_SYMMETRIC = 1u32 << 30;
    }
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
pub struct SignCmd {
    pub handle: ContextHandle,
    pub label: [u8; DPE_PROFILE.get_hash_size()],
    pub flags: SignFlags,
    pub digest: [u8; DPE_PROFILE.get_hash_size()],
}

impl SignCmd {
    const fn uses_symmetric(&self) -> bool {
        self.flags.contains(SignFlags::IS_SYMMETRIC)
    }

    /// Signs `digest` using ECDSA
    ///
    /// # Arguments
    ///
    /// * `dpe` - DPE instance
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `idx` - The index of the context where the measurement hash is computed from
    /// * `digest` - The data to be signed
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn ecdsa_sign(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        idx: usize,
        digest: &Digest,
    ) -> Result<EcdsaSig, DpeErrorCode> {
        let algs = DPE_PROFILE.alg_len();
        let cdi_digest = dpe.compute_measurement_hash(env, idx)?;
        let cdi = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &cdi_digest, b"DPE")?;
        let key_pair = env.crypto.derive_key_pair(algs, &cdi, &self.label, b"ECC");
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

    /// Signs `digest` using an HMAC
    ///
    /// # Arguments
    ///
    /// * `dpe` - DPE instance
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `idx` - The index of the context where the measurement hash is computed from
    /// * `digest` - The data to be signed
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[cfg(not(feature = "disable_is_symmetric"))]
    fn hmac_sign(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        idx: usize,
        digest: &Digest,
    ) -> Result<HmacSig, DpeErrorCode> {
        let algs = DPE_PROFILE.alg_len();
        let cdi_digest = dpe.compute_measurement_hash(env, idx)?;
        let cdi = env
            .crypto
            .derive_cdi(DPE_PROFILE.alg_len(), &cdi_digest, b"DPE");
        if cfi_launder(cdi.is_ok()) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(cdi.is_ok());
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(cdi.is_err());
        }
        Ok(env
            .crypto
            .hmac_sign_with_derived(algs, &cdi?, &self.label, b"HMAC", digest)?)
    }
}

impl CommandExecution for SignCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure the operation is supported.
        if !dpe.support.is_symmetric() && self.uses_symmetric() {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        let idx = dpe.get_active_context_pos(&self.handle, locality)?;
        let context = &dpe.contexts[idx];

        if context.context_type == ContextType::Simulation {
            return Err(DpeErrorCode::InvalidArgument);
        }

        cfg_if! {
            if #[cfg(not(feature = "no-cfi"))] {
                cfi_assert!(dpe.support.is_symmetric() || !self.uses_symmetric());
                cfi_assert_ne(context.context_type, ContextType::Simulation);
            }
        }

        let digest = Digest::new(&self.digest)?;
        let EcdsaSig { r, s } = if !self.uses_symmetric() {
            self.ecdsa_sign(dpe, env, idx, &digest)?
        } else {
            cfg_if! {
                if #[cfg(not(feature = "disable_is_symmetric"))] {
                    let algs = DPE_PROFILE.alg_len();
                    let r = self.hmac_sign(dpe, env, idx, &digest)?;
                    let s = CryptoBuf::default(algs);
                    EcdsaSig { r, s }
                }
                else {
                    Err(DpeErrorCode::ArgumentNotSupported)?
                }
            }
        };

        let sig_r_or_hmac: [u8; DPE_PROFILE.get_ecc_int_size()] = r
            .bytes()
            .try_into()
            .map_err(|_| DpeErrorCode::InternalError)?;

        let sig_s: [u8; DPE_PROFILE.get_ecc_int_size()] = s
            .bytes()
            .try_into()
            .map_err(|_| DpeErrorCode::InternalError)?;

        // Rotate the handle if it isn't the default context.
        dpe.roll_onetime_use_handle(env, idx)?;

        Ok(Response::Sign(SignResp {
            new_context_handle: dpe.contexts[idx].handle,
            sig_r_or_hmac,
            sig_s,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{
            certify_key::CertifyKeyCmd,
            certify_key::CertifyKeyFlags,
            derive_context::DeriveContextFlags,
            tests::{TEST_DIGEST, TEST_LABEL},
            Command, CommandHdr, DeriveContextCmd, InitCtxCmd,
        },
        dpe_instance::tests::{TestTypes, RANDOM_HANDLE, SIMULATION_HANDLE, TEST_LOCALITIES},
        support::{test::SUPPORT, Support},
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::OpensslCrypto;
    use openssl::x509::X509;
    use openssl::{bn::BigNum, ecdsa::EcdsaSig};
    use platform::default::DefaultPlatform;
    use zerocopy::IntoBytes;

    const TEST_SIGN_CMD: SignCmd = SignCmd {
        handle: SIMULATION_HANDLE,
        label: TEST_LABEL,
        flags: SignFlags(0x1234_5678),
        digest: TEST_DIGEST,
    };

    #[test]
    fn test_deserialize_sign() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new_for_test(Command::SIGN).as_bytes().to_vec();
        command.extend(TEST_SIGN_CMD.as_bytes());
        assert_eq!(
            Ok(Command::Sign(&TEST_SIGN_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_uses_symmetric() {
        CfiCounter::reset_for_test();
        // No flags set.
        assert!(!SignCmd {
            flags: SignFlags::empty(),
            ..TEST_SIGN_CMD
        }
        .uses_symmetric());

        // Just is-symmetric flag set.
        assert!(SignCmd {
            flags: SignFlags::IS_SYMMETRIC,
            ..TEST_SIGN_CMD
        }
        .uses_symmetric());
    }

    #[test]
    fn test_bad_command_inputs() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT).unwrap();

        // Bad argument
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            SignCmd {
                handle: ContextHandle([0xff; ContextHandle::SIZE]),
                label: TEST_LABEL,
                flags: SignFlags::IS_SYMMETRIC,
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Bad handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            SignCmd {
                handle: ContextHandle([0xff; ContextHandle::SIZE]),
                label: TEST_LABEL,
                flags: SignFlags::empty(),
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Wrong locality.
        assert!(dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .is_ok());
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            SignCmd {
                handle: ContextHandle::default(),
                label: TEST_LABEL,
                flags: SignFlags::empty(),
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        );

        // Simulation contexts should not support the Sign command.
        InitCtxCmd::new_simulation()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();
        assert!(dpe
            .get_active_context_pos(&RANDOM_HANDLE, TEST_LOCALITIES[0])
            .is_ok());
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            SignCmd {
                handle: RANDOM_HANDLE,
                label: TEST_LABEL,
                flags: SignFlags::empty(),
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_asymmetric() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT).unwrap();

        for i in 0..3 {
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [i; DPE_PROFILE.get_hash_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
                tci_type: i as u32,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();
        }

        let sig = {
            let cmd = SignCmd {
                handle: ContextHandle::default(),
                label: TEST_LABEL,
                flags: SignFlags::empty(),
                digest: TEST_DIGEST,
            };
            let resp = match cmd.execute(&mut dpe, &mut env, TEST_LOCALITIES[0]).unwrap() {
                Response::Sign(resp) => resp,
                _ => panic!("Incorrect response type"),
            };

            EcdsaSig::from_private_components(
                BigNum::from_slice(&resp.sig_r_or_hmac).unwrap(),
                BigNum::from_slice(&resp.sig_s).unwrap(),
            )
            .unwrap()
        };

        let ec_pub_key = {
            let cmd = CertifyKeyCmd {
                handle: ContextHandle::default(),
                flags: CertifyKeyFlags::empty(),
                label: TEST_LABEL,
                format: CertifyKeyCmd::FORMAT_X509,
            };
            let certify_resp = match cmd.execute(&mut dpe, &mut env, TEST_LOCALITIES[0]).unwrap() {
                Response::CertifyKey(resp) => resp,
                _ => panic!("Incorrect response type"),
            };
            let x509 =
                X509::from_der(&certify_resp.cert[..certify_resp.cert_size.try_into().unwrap()])
                    .unwrap();
            x509.public_key().unwrap().ec_key().unwrap()
        };

        assert!(sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap());
    }

    #[test]
    fn test_symmetric() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe =
            DpeInstance::new(&mut env, Support::AUTO_INIT | Support::IS_SYMMETRIC).unwrap();

        let cmd = SignCmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: SignFlags::IS_SYMMETRIC,
            digest: TEST_DIGEST,
        };
        let resp = match cmd.execute(&mut dpe, &mut env, TEST_LOCALITIES[0]).unwrap() {
            Response::Sign(resp) => resp,
            _ => panic!("Incorrect response type"),
        };

        let idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        // Check that r is equal to the HMAC over the digest
        assert_eq!(
            resp.sig_r_or_hmac,
            cmd.hmac_sign(&mut dpe, &mut env, idx, &Digest::new(&TEST_DIGEST).unwrap(),)
                .unwrap()
                .bytes()
        );
        // Check that s is a buffer of all 0s
        assert!(&resp.sig_s.iter().all(|&b| b == 0x0));
    }
}
