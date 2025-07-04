// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ContextHandle, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response, SignResp},
    DPE_PROFILE,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_assert_ne};
use cfg_if::cfg_if;
use crypto::{ecdsa::EcdsaSignature, Crypto, Digest, Signature};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct SignFlags(pub u32);

bitflags! {
    impl SignFlags: u32 {}
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct SignCmd {
    pub handle: ContextHandle,
    pub label: [u8; DPE_PROFILE.hash_size()],
    pub flags: SignFlags,
    pub digest: [u8; DPE_PROFILE.hash_size()],
}

impl SignCmd {
    /// Signs `digest` using ECDSA
    ///
    /// # Arguments
    ///
    /// * `dpe` - DPE instance
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `idx` - The index of the context where the measurement hash is computed from
    /// * `digest` - The data to be signed
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn sign(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        idx: usize,
        digest: &Digest,
    ) -> Result<Signature, DpeErrorCode> {
        let cdi_digest = dpe.compute_measurement_hash(env, idx)?;
        let cdi = env.crypto.derive_cdi(&cdi_digest, b"DPE")?;
        let key_pair = env.crypto.derive_key_pair(&cdi, &self.label, b"ECC");
        if cfi_launder(key_pair.is_ok()) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_ok());
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_err());
        }
        let (priv_key, pub_key) = key_pair?;

        Ok(env.crypto.sign_with_derived(digest, &priv_key, &pub_key)?)
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
        let idx = env.state.get_active_context_pos(&self.handle, locality)?;
        let context = &env.state.contexts[idx];

        if context.context_type == ContextType::Simulation {
            return Err(DpeErrorCode::InvalidArgument);
        }

        cfg_if! {
            if #[cfg(not(feature = "no-cfi"))] {
                cfi_assert_ne(context.context_type, ContextType::Simulation);
            }
        }

        #[cfg(feature = "dpe_profile_p256_sha256")]
        let digest = Digest::Sha256(
            crypto::Sha256::read_from_bytes(&self.digest)
                .map_err(|_| DpeErrorCode::Crypto(crypto::CryptoError::Size))?,
        );

        #[cfg(feature = "dpe_profile_p384_sha384")]
        let digest = Digest::Sha384(
            crypto::Sha384::read_from_bytes(&self.digest)
                .map_err(|_| DpeErrorCode::Crypto(crypto::CryptoError::Size))?,
        );

        let sig = match self.sign(dpe, env, idx, &digest)? {
            #[cfg(feature = "dpe_profile_p256_sha256")]
            Signature::Ecdsa(EcdsaSignature::Ecdsa256(sig)) => sig,
            #[cfg(feature = "dpe_profile_p384_sha384")]
            Signature::Ecdsa(EcdsaSignature::Ecdsa384(sig)) => sig,
            _ => Err(DpeErrorCode::InvalidArgument)?,
        };

        let (&sig_r, &sig_s) = sig.as_slice()?;

        // Rotate the handle if it isn't the default context.
        dpe.roll_onetime_use_handle(env, idx)?;

        Ok(Response::Sign(SignResp {
            new_context_handle: env.state.contexts[idx].handle,
            sig_r,
            sig_s,
            resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{
            certify_key::{CertifyKeyCmd, CertifyKeyFlags},
            derive_context::DeriveContextFlags,
            tests::{PROFILES, TEST_DIGEST, TEST_LABEL},
            Command, CommandHdr, DeriveContextCmd, InitCtxCmd,
        },
        dpe_instance::tests::{
            test_env, test_state, RANDOM_HANDLE, SIMULATION_HANDLE, TEST_LOCALITIES,
        },
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use openssl::x509::X509;
    use openssl::{bn::BigNum, ecdsa::EcdsaSig};
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
        for p in PROFILES {
            let mut command = CommandHdr::new(p, Command::SIGN).as_bytes().to_vec();
            command.extend(TEST_SIGN_CMD.as_bytes());
            assert_eq!(
                Ok(Command::Sign(&TEST_SIGN_CMD)),
                Command::deserialize(p, &command)
            );
        }
    }

    #[test]
    fn test_bad_command_inputs() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

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
        assert!(env
            .state
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
        assert!(env
            .state
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
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        for i in 0..3 {
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [i; DPE_PROFILE.hash_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
                tci_type: i as u32,
                target_locality: 0,
                svn: 0,
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
                BigNum::from_slice(&resp.sig_r).unwrap(),
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
}
