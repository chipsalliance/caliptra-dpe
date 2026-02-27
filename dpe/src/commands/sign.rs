// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ContextHandle, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    mutresp, okref,
    response::DpeErrorCode,
    DpeProfile,
};
use bitflags::bitflags;
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::cfi_launder;
#[cfg(feature = "cfi")]
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_assert_ne};
use cfg_if::cfg_if;
use core::mem::size_of_val;
#[cfg(any(feature = "p256", feature = "p384"))]
use crypto::ecdsa::EcdsaSignature;
use crypto::{Crypto, SignData, Signature};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct SignFlags(pub u32);

bitflags! {
    impl SignFlags: u32 {
        const IS_RAW = 1 << 0;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignCommand<'a> {
    #[cfg(feature = "p256")]
    P256(&'a SignP256Cmd),
    #[cfg(feature = "p384")]
    P384(&'a SignP384Cmd),
    #[cfg(feature = "ml-dsa")]
    Mldsa87(&'a SignMldsa87Cmd),
    #[cfg(feature = "ml-dsa")]
    Mldsa87Raw {
        handle: &'a ContextHandle,
        label: &'a [u8],
        raw_data: &'a [u8],
    },
}

impl SignCommand<'_> {
    pub fn deserialize(profile: DpeProfile, bytes: &[u8]) -> Result<SignCommand, DpeErrorCode> {
        match profile {
            #[cfg(feature = "p256")]
            DpeProfile::P256Sha256 => SignCommand::parse_command(SignCommand::P256, bytes),
            #[cfg(feature = "p384")]
            DpeProfile::P384Sha384 => SignCommand::parse_command(SignCommand::P384, bytes),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => SignCommand::deserialize_mldsa87(bytes),
            _ => Err(DpeErrorCode::InvalidArgument)?,
        }
    }

    #[cfg(feature = "ml-dsa")]
    fn deserialize_mldsa87(bytes: &[u8]) -> Result<SignCommand, DpeErrorCode> {
        // We only need the first 68 bytes (handle + label + flags) to inspect the flag.
        const FIXED_PREFIX_SIZE: usize = 16 + 48 + 4;

        if bytes.len() < FIXED_PREFIX_SIZE {
            return Err(DpeErrorCode::InvalidArgument);
        }

        // Read flags from buffer (little endian at offset 64).
        let flags_bytes: &[u8; 4] = &bytes[16 + 48..FIXED_PREFIX_SIZE]
            .try_into()
            .map_err(|_| DpeErrorCode::InvalidArgument)?;
        let flags = SignFlags(u32::from_le_bytes(*flags_bytes));

        if flags.contains(SignFlags::IS_RAW) {
            // Must have size field following the fixed prefix.
            if bytes.len() < FIXED_PREFIX_SIZE + 4 {
                return Err(DpeErrorCode::InvalidArgument);
            }

            let size_bytes: &[u8; 4] = &bytes[FIXED_PREFIX_SIZE..FIXED_PREFIX_SIZE + 4]
                .try_into()
                .map_err(|_| DpeErrorCode::InvalidArgument)?;
            let size = u32::from_le_bytes(*size_bytes) as usize;

            let data_start = FIXED_PREFIX_SIZE + 4;
            if data_start + size > bytes.len() {
                return Err(DpeErrorCode::InvalidArgument);
            }

            let handle_slice = &bytes[0..16];
            let label_slice = &bytes[16..64];
            let raw_data = &bytes[data_start..data_start + size];

            let handle = <ContextHandle as FromBytes>::ref_from_prefix(handle_slice)
                .map_err(|_| DpeErrorCode::InvalidArgument)?
                .0;

            Ok(SignCommand::Mldsa87Raw {
                handle,
                label: label_slice,
                raw_data,
            })
        } else {
            // Legacy fixed-size command, safe to parse normally.
            SignCommand::parse_command(SignCommand::Mldsa87, bytes)
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

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "p256")]
            SignCommand::P256(cmd) => cmd.as_bytes(),
            #[cfg(feature = "p384")]
            SignCommand::P384(cmd) => cmd.as_bytes(),
            #[cfg(feature = "ml-dsa")]
            SignCommand::Mldsa87(cmd) => cmd.as_bytes(),
            #[cfg(feature = "ml-dsa")]
            SignCommand::Mldsa87Raw { .. } => &[], // Raw variant doesn't have a fixed representation
        }
    }
}

impl CommandExecution for SignCommand<'_> {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn execute_serialized(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
        out: &mut [u8],
    ) -> Result<usize, DpeErrorCode> {
        let (handle, label, data) = match *self {
            #[cfg(feature = "p256")]
            SignCommand::P256(cmd) => (
                &cmd.handle,
                cmd.label.as_slice(),
                SignData::Digest(cmd.digest.into()),
            ),
            #[cfg(feature = "p384")]
            SignCommand::P384(cmd) => (
                &cmd.handle,
                cmd.label.as_slice(),
                SignData::Digest(cmd.digest.into()),
            ),
            #[cfg(feature = "ml-dsa")]
            SignCommand::Mldsa87(cmd) => (
                &cmd.handle,
                cmd.label.as_slice(),
                SignData::Mu(cmd.digest.into()),
            ),
            #[cfg(feature = "ml-dsa")]
            SignCommand::Mldsa87Raw {
                handle,
                label,
                raw_data,
            } => (handle, label, SignData::Raw(raw_data)),
        };
        let idx = env.state.get_active_context_pos(handle, locality)?;
        let context = &env.state.contexts[idx];

        if context.context_type == ContextType::Simulation {
            return Err(DpeErrorCode::InvalidArgument);
        }

        cfg_if! {
            if #[cfg(feature = "cfi")] {
                cfi_assert_ne(context.context_type, ContextType::Simulation);
            }
        }

        let sig = sign(dpe, env, idx, label, &data);
        match okref(&sig)? {
            #[cfg(feature = "p256")]
            Signature::Ecdsa(EcdsaSignature::Ecdsa256(sig)) => {
                use crate::response::SignP256Resp;
                let response = mutresp::<SignP256Resp>(dpe.profile, out)?;

                // Rotate the handle if it isn't the default context.
                dpe.roll_onetime_use_handle(env, idx)?;
                let (&sig_r, &sig_s) = sig.as_slice();
                *response = SignP256Resp {
                    new_context_handle: env.state.contexts[idx].handle,
                    sig_r,
                    sig_s,
                    resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
                };
                Ok(size_of_val(response))
            }
            #[cfg(feature = "p384")]
            Signature::Ecdsa(EcdsaSignature::Ecdsa384(sig)) => {
                use crate::response::SignP384Resp;
                let response = mutresp::<SignP384Resp>(dpe.profile, out)?;

                // Rotate the handle if it isn't the default context.
                dpe.roll_onetime_use_handle(env, idx)?;
                let (&sig_r, &sig_s) = sig.as_slice();
                *response = SignP384Resp {
                    new_context_handle: env.state.contexts[idx].handle,
                    sig_r,
                    sig_s,
                    resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
                };
                Ok(size_of_val(response))
            }
            #[cfg(feature = "ml-dsa")]
            Signature::MlDsa(crypto::ml_dsa::MldsaSignature(sig)) => {
                use crate::response::SignMlDsaResp;
                let response = mutresp::<SignMlDsaResp>(dpe.profile, out)?;

                // Rotate the handle if it isn't the default context.
                dpe.roll_onetime_use_handle(env, idx)?;
                *response = SignMlDsaResp {
                    new_context_handle: env.state.contexts[idx].handle,
                    sig: *sig,
                    _padding: [0; 1],
                    resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
                };
                Ok(size_of_val(response))
            }
            _ => Err(DpeErrorCode::InvalidArgument)?,
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
    data: &SignData,
) -> Result<Signature, DpeErrorCode> {
    let cdi_digest = dpe.compute_measurement_hash(env, idx)?;
    let cdi = env.crypto.derive_cdi(&cdi_digest, b"DPE")?;
    let profile = dpe.profile;
    let context = profile.key_context();
    let key_pair = env.crypto.derive_key_pair(&cdi, label, context);
    if cfi_launder(key_pair.is_ok()) {
        #[cfg(feature = "cfi")]
        cfi_assert!(key_pair.is_ok());
    } else {
        #[cfg(feature = "cfi")]
        cfi_assert!(key_pair.is_err());
    }
    let (priv_key, pub_key) = key_pair?;

    Ok(env.crypto.sign_with_derived(data, &priv_key, &pub_key)?)
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct SignP256Cmd {
    pub handle: ContextHandle,
    pub label: [u8; 32],
    pub flags: SignFlags,
    pub digest: [u8; 32],
}

#[cfg(feature = "p256")]
impl CommandExecution for SignP256Cmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn execute_serialized(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
        out: &mut [u8],
    ) -> Result<usize, DpeErrorCode> {
        SignCommand::P256(self).execute_serialized(dpe, env, locality, out)
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

#[cfg(feature = "p384")]
impl CommandExecution for SignP384Cmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn execute_serialized(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
        out: &mut [u8],
    ) -> Result<usize, DpeErrorCode> {
        SignCommand::P384(self).execute_serialized(dpe, env, locality, out)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct SignMldsa87Cmd {
    pub handle: ContextHandle,
    pub label: [u8; 48],
    pub flags: SignFlags,
    pub digest: [u8; 64],
}

#[cfg(feature = "ml-dsa")]
impl CommandExecution for SignMldsa87Cmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn execute_serialized(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
        out: &mut [u8],
    ) -> Result<usize, DpeErrorCode> {
        SignCommand::Mldsa87(self).execute_serialized(dpe, env, locality, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "ml-dsa")]
    use crate::commands::{sign::SignMldsa87Cmd as SignCmd, CertifyKeyMldsa87Cmd as CertifyKeyCmd};
    #[cfg(feature = "p256")]
    use crate::commands::{sign::SignP256Cmd as SignCmd, CertifyKeyP256Cmd as CertifyKeyCmd};
    #[cfg(feature = "p384")]
    use crate::commands::{sign::SignP384Cmd as SignCmd, CertifyKeyP384Cmd as CertifyKeyCmd};
    use crate::{
        commands::{
            certify_key::{CertifyKeyCommand, CertifyKeyFlags},
            derive_context::DeriveContextFlags,
            tests::{TEST_DIGEST, TEST_LABEL},
            Command, CommandHdr, DeriveContextCmd, InitCtxCmd,
        },
        dpe_instance::tests::{
            test_env, test_state, DPE_PROFILE, RANDOM_HANDLE, SIMULATION_HANDLE, TEST_LOCALITIES,
        },
        response::{Response, SignResp},
        tci::TciMeasurement,
    };
    use caliptra_cfi_lib::CfiCounter;
    use openssl::x509::X509;
    use openssl::{bn::BigNum, ecdsa::EcdsaSig};
    use zerocopy::IntoBytes;

    #[cfg(feature = "ml-dsa")]
    const TEST_SIGN_DIGEST: [u8; 64] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    ];
    #[cfg(not(feature = "ml-dsa"))]
    const TEST_SIGN_DIGEST: [u8; DPE_PROFILE.hash_size()] = TEST_DIGEST;

    const TEST_SIGN_CMD: SignCmd = SignCmd {
        handle: SIMULATION_HANDLE,
        label: TEST_LABEL,
        flags: SignFlags(0x1234_5678),
        digest: TEST_SIGN_DIGEST,
    };

    #[test]
    fn test_deserialize_sign() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new(DPE_PROFILE, Command::SIGN)
            .as_bytes()
            .to_vec();
        command.extend(TEST_SIGN_CMD.as_bytes());

        #[cfg(feature = "p256")]
        let expected = Command::Sign(SignCommand::P256(&TEST_SIGN_CMD));
        #[cfg(feature = "p384")]
        let expected = Command::Sign(SignCommand::P384(&TEST_SIGN_CMD));
        #[cfg(feature = "ml-dsa")]
        let expected = Command::Sign(SignCommand::Mldsa87(&TEST_SIGN_CMD));
        assert_eq!(Ok(expected), Command::deserialize(DPE_PROFILE, &command));
    }

    #[test]
    fn test_bad_command_inputs() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        // Bad handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            SignCmd {
                handle: ContextHandle([0xff; ContextHandle::SIZE]),
                label: TEST_LABEL,
                flags: SignFlags::empty(),
                digest: TEST_SIGN_DIGEST
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
                digest: TEST_SIGN_DIGEST
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
                digest: TEST_SIGN_DIGEST
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_asymmetric() {
        CfiCounter::reset_for_test();
        let mut state = test_state();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

        for i in 0..3 {
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: TciMeasurement([i; DPE_PROFILE.hash_size()]),
                flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
                tci_type: i as u32,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();
        }

        let sign_resp = {
            let cmd = SignCmd {
                handle: ContextHandle::default(),
                label: TEST_LABEL,
                flags: SignFlags::empty(),
                digest: TEST_SIGN_DIGEST,
            };
            match cmd.execute(&mut dpe, &mut env, TEST_LOCALITIES[0]).unwrap() {
                Response::Sign(resp) => resp,
                _ => panic!("Incorrect response type"),
            }
        };

        let certify_resp = {
            let cmd = CertifyKeyCmd {
                handle: ContextHandle::default(),
                flags: CertifyKeyFlags::empty(),
                label: TEST_LABEL,
                format: CertifyKeyCommand::FORMAT_X509,
            };
            match CertifyKeyCommand::from(&cmd)
                .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
                .unwrap()
            {
                Response::CertifyKey(resp) => resp,
                _ => panic!("Incorrect response type"),
            }
        };
        let cert_bytes = certify_resp.cert().unwrap();

        match DPE_PROFILE {
            #[cfg(any(feature = "p256", feature = "p384"))]
            DpeProfile::P256Sha256 | DpeProfile::P384Sha384 => {
                let (r, s) = match sign_resp {
                    #[cfg(feature = "p256")]
                    SignResp::P256(resp) => (resp.sig_r.to_vec(), resp.sig_s.to_vec()),
                    #[cfg(feature = "p384")]
                    SignResp::P384(resp) => (resp.sig_r.to_vec(), resp.sig_s.to_vec()),
                    _ => panic!("Incorrect response type"),
                };
                let sig = EcdsaSig::from_private_components(
                    BigNum::from_slice(&r).unwrap(),
                    BigNum::from_slice(&s).unwrap(),
                )
                .unwrap();

                let x509 = X509::from_der(cert_bytes).unwrap();
                let pub_key = x509.public_key().unwrap().ec_key().unwrap();

                assert!(sig.verify(&TEST_SIGN_DIGEST, &pub_key).unwrap());
            }
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => {
                use ml_dsa::signature::Verifier;
                use ml_dsa::{EncodedSignature, EncodedVerifyingKey, VerifyingKey};
                use x509_parser::nom::Parser;
                use x509_parser::prelude::*;
                use x509_parser::public_key::PublicKey;

                let sig_bytes = match sign_resp {
                    SignResp::MlDsa(resp) => resp.sig,
                    _ => panic!("Incorrect response type"),
                };
                let encoded_sig =
                    EncodedSignature::<ml_dsa::MlDsa87>::try_from(sig_bytes.as_slice())
                        .expect("Invalid signature length");
                let sig =
                    ml_dsa::Signature::decode(&encoded_sig).expect("Error decoding signature");

                let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
                let (_, cert) = parser.parse(cert_bytes).expect("Failed to parse cert");

                let pub_key_parsed = cert.public_key().parsed().unwrap();
                let key_bytes = match pub_key_parsed {
                    PublicKey::Unknown(k) => k,
                    _ => panic!("Expected unknown key type for ML-DSA"),
                };

                let encoded_vk =
                    EncodedVerifyingKey::<ml_dsa::MlDsa87>::try_from(key_bytes).unwrap();
                let vk = VerifyingKey::<ml_dsa::MlDsa87>::decode(&encoded_vk);

                assert!(vk.verify_mu((&TEST_SIGN_DIGEST).into(), &sig));
            }
            _ => panic!("Unsupported profile"),
        }
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn test_deserialize_sign_raw_mode() {
        CfiCounter::reset_for_test();
        // Test raw mode deserialization
        // Format: handle(16) + label(48) + flags(4) + size(4) + data(variable)
        let mut cmd_bytes = Vec::new();

        // Add handle
        cmd_bytes.extend(SIMULATION_HANDLE.0.iter());

        // Add label (48 bytes)
        cmd_bytes.extend(&TEST_LABEL);

        // Add flags with IS_RAW flag set (bit 0)
        let flags_with_raw = SignFlags::IS_RAW;
        cmd_bytes.extend(flags_with_raw.0.to_le_bytes().iter());

        // Add size
        let raw_data = b"test_raw_data_to_sign";
        let size = (raw_data.len() as u32).to_le_bytes();
        cmd_bytes.extend(size.iter());

        // Add raw data
        cmd_bytes.extend(raw_data.iter());

        // Test deserialization
        let cmd = SignCommand::deserialize(DPE_PROFILE, &cmd_bytes);
        assert!(cmd.is_ok());

        match cmd.unwrap() {
            #[cfg(feature = "ml-dsa")]
            SignCommand::Mldsa87Raw {
                handle,
                label,
                raw_data: data,
            } => {
                assert_eq!(handle.0, SIMULATION_HANDLE.0);
                assert_eq!(label, &TEST_LABEL);
                assert_eq!(data, raw_data);
            }
            _ => panic!("Expected Mldsa87Raw variant"),
        }
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn test_deserialize_sign_raw_mode_invalid_buffer() {
        CfiCounter::reset_for_test();
        // Test that invalid buffer size is caught
        let mut cmd_bytes = Vec::new();

        // Add handle
        cmd_bytes.extend(SIMULATION_HANDLE.0.iter());

        // Add label (48 bytes)
        cmd_bytes.extend(&TEST_LABEL);

        // Add flags with IS_RAW flag set
        let flags_with_raw = SignFlags::IS_RAW;
        cmd_bytes.extend(flags_with_raw.0.to_le_bytes().iter());

        // Add size that exceeds buffer
        cmd_bytes.extend([255, 0, 0, 0].iter()); // Size of 255

        // Add only 10 bytes of data (less than promised)
        cmd_bytes.extend(b"short_data".iter());

        // Test deserialization should fail
        let cmd = SignCommand::deserialize(DPE_PROFILE, &cmd_bytes);
        assert!(cmd.is_err());
        assert_eq!(cmd.unwrap_err(), DpeErrorCode::InvalidArgument);
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn test_deserialize_sign_non_raw_mode() {
        CfiCounter::reset_for_test();
        // Test that non-raw mode still works (backward compatibility)
        let mut command = CommandHdr::new(DPE_PROFILE, Command::SIGN)
            .as_bytes()
            .to_vec();
        command.extend(TEST_SIGN_CMD.as_bytes());

        let cmd = Command::deserialize(DPE_PROFILE, &command);
        assert!(cmd.is_ok());

        match cmd.unwrap() {
            Command::Sign(SignCommand::Mldsa87(_)) => {
                // Expected
            }
            _ => panic!("Expected Mldsa87 variant for non-raw mode"),
        }
    }
}
