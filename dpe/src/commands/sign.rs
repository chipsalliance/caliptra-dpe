// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ContextHandle, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response, SignResp},
    DpeProfile,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_assert_ne};
use cfg_if::cfg_if;
use crypto::ecdsa::EcdsaSignature;
use crypto::{Crypto, Digest, Signature};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct SignFlags(pub u32);

bitflags! {
    impl SignFlags: u32 {}
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignCommand<'a> {
    #[cfg(feature = "dpe_profile_p256_sha256")]
    P256(&'a SignP256Cmd),
    #[cfg(feature = "dpe_profile_p384_sha384")]
    P384(&'a SignP384Cmd),
}

impl SignCommand<'_> {
    pub fn deserialize(profile: DpeProfile, bytes: &[u8]) -> Result<SignCommand, DpeErrorCode> {
        match profile {
            #[cfg(feature = "dpe_profile_p256_sha256")]
            DpeProfile::P256Sha256 => SignCommand::parse_command(SignCommand::P256, bytes),
            #[cfg(feature = "dpe_profile_p384_sha384")]
            DpeProfile::P384Sha384 => SignCommand::parse_command(SignCommand::P384, bytes),
            _ => Err(DpeErrorCode::InvalidArgument)?,
        }
    }
    pub fn parse_command<'a, T: FromBytes + KnownLayout + Immutable + 'a>(
        build: impl FnOnce(&'a T) -> SignCommand<'a>,
        bytes: &'a [u8],
    ) -> Result<SignCommand<'a>, DpeErrorCode> {
        let (prefix, _remaining_bytes) =
            T::ref_from_prefix(bytes).map_err(|_| DpeErrorCode::InvalidArgument)?;
        Ok(build(prefix))
    }
}

impl CommandExecution for SignCommand<'_> {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        match self {
            #[cfg(feature = "dpe_profile_p256_sha256")]
            SignCommand::P256(cmd) => cmd.execute(dpe, env, locality),
            #[cfg(feature = "dpe_profile_p384_sha384")]
            SignCommand::P384(cmd) => cmd.execute(dpe, env, locality),
        }
    }
}

/// Signs `digest` using ECDSA
///
/// # Arguments
///
/// * `dpe` - DPE instance
/// * `env` - DPE environment containing Crypto and Platform implementations
/// * `idx` - The index of the context where the measurement hash is computed from
/// * `digest` - The data to be signed
fn sign(
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<impl DpeTypes>,
    idx: usize,
    label: &[u8],
    digest: &Digest,
) -> Result<Signature, DpeErrorCode> {
    let cdi_digest = dpe.compute_measurement_hash(env, idx)?;
    let cdi = env.crypto.derive_cdi(&cdi_digest, b"DPE")?;
    let key_pair = env.crypto.derive_key_pair(&cdi, label, b"ECC");
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

fn execute(
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<impl DpeTypes>,
    handle: &ContextHandle,
    label: &[u8],
    digest: &[u8],
    locality: u32,
) -> Result<Response, DpeErrorCode> {
    let idx = env.state.get_active_context_pos(handle, locality)?;
    let context = &env.state.contexts[idx];

    if context.context_type == ContextType::Simulation {
        return Err(DpeErrorCode::InvalidArgument);
    }

    cfg_if! {
        if #[cfg(not(feature = "no-cfi"))] {
            cfi_assert_ne(context.context_type, ContextType::Simulation);
        }
    }

    let digest = match dpe.profile {
        #[cfg(feature = "dpe_profile_p256_sha256")]
        crate::DpeProfile::P256Sha256 => Digest::Sha256(
            crypto::Sha256::read_from_bytes(digest)
                .map_err(|_| DpeErrorCode::Crypto(crypto::CryptoError::Size))?,
        ),
        #[cfg(feature = "dpe_profile_p384_sha384")]
        crate::DpeProfile::P384Sha384 => Digest::Sha384(
            crypto::Sha384::read_from_bytes(digest)
                .map_err(|_| DpeErrorCode::Crypto(crypto::CryptoError::Size))?,
        ),
        _ => Err(DpeErrorCode::InvalidArgument)?,
    };

    let mut response = match sign(dpe, env, idx, label, &digest)? {
        #[cfg(feature = "dpe_profile_p256_sha256")]
        Signature::Ecdsa(EcdsaSignature::Ecdsa256(sig)) => {
            use crate::response::SignP256Resp;
            let (&sig_r, &sig_s) = sig.as_slice();
            SignResp::P256(SignP256Resp {
                new_context_handle: ContextHandle::new_invalid(),
                sig_r,
                sig_s,
                resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
            })
        }
        #[cfg(feature = "dpe_profile_p384_sha384")]
        Signature::Ecdsa(EcdsaSignature::Ecdsa384(sig)) => {
            use crate::response::SignP384Resp;
            let (&sig_r, &sig_s) = sig.as_slice();
            SignResp::P384(SignP384Resp {
                new_context_handle: ContextHandle::new_invalid(),
                sig_r,
                sig_s,
                resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
            })
        }
        _ => Err(DpeErrorCode::InvalidArgument)?,
    };

    // Rotate the handle if it isn't the default context.
    dpe.roll_onetime_use_handle(env, idx)?;
    response.set_handle(&env.state.contexts[idx].handle);

    Ok(Response::Sign(response))
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct SignP256Cmd {
    pub handle: ContextHandle,
    pub label: [u8; 32],
    pub flags: SignFlags,
    pub digest: [u8; 32],
}

impl CommandExecution for SignP256Cmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        execute(dpe, env, &self.handle, &self.label, &self.digest, locality)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct SignP384Cmd {
    pub handle: ContextHandle,
    pub label: [u8; 48],
    pub flags: SignFlags,
    pub digest: [u8; 48],
}

impl CommandExecution for SignP384Cmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        execute(dpe, env, &self.handle, &self.label, &self.digest, locality)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "dpe_profile_p256_sha256")]
    use crate::commands::sign::SignP256Cmd as SignCmd;
    #[cfg(feature = "dpe_profile_p384_sha384")]
    use crate::commands::sign::SignP384Cmd as SignCmd;
    use crate::{
        commands::{
            certify_key::{CertifyKeyCmd, CertifyKeyFlags},
            derive_context::DeriveContextFlags,
            tests::{TEST_DIGEST, TEST_LABEL},
            Command, CommandHdr, DeriveContextCmd, InitCtxCmd,
        },
        dpe_instance::tests::{
            test_env, test_state, RANDOM_HANDLE, SIMULATION_HANDLE, TEST_LOCALITIES,
        },
        DPE_PROFILE,
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
        let mut command = CommandHdr::new(DPE_PROFILE, Command::SIGN)
            .as_bytes()
            .to_vec();
        command.extend(TEST_SIGN_CMD.as_bytes());

        #[cfg(feature = "dpe_profile_p256_sha256")]
        let expected = Command::Sign(SignCommand::P256(&TEST_SIGN_CMD));
        #[cfg(feature = "dpe_profile_p384_sha384")]
        let expected = Command::Sign(SignCommand::P384(&TEST_SIGN_CMD));
        assert_eq!(Ok(expected), Command::deserialize(DPE_PROFILE, &command));
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
                flags: DeriveContextFlags::MAKE_DEFAULT,
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

            let (r, s) = match resp {
                #[cfg(feature = "dpe_profile_p256_sha256")]
                SignResp::P256(resp) => (resp.sig_r, resp.sig_s),
                #[cfg(feature = "dpe_profile_p384_sha384")]
                SignResp::P384(resp) => (resp.sig_r, resp.sig_s),
            };

            EcdsaSig::from_private_components(
                BigNum::from_slice(&r).unwrap(),
                BigNum::from_slice(&s).unwrap(),
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
