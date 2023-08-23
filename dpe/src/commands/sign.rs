// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ContextHandle, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DpeErrorCode, Response, ResponseHdr, SignResp},
    DPE_PROFILE,
};
use crypto::{Crypto, CryptoBuf, Digest, EcdsaSig, HmacSig};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes)]
#[cfg_attr(test, derive(zerocopy::AsBytes))]
pub struct SignCmd {
    handle: ContextHandle,
    label: [u8; DPE_PROFILE.get_hash_size()],
    flags: u32,
    digest: [u8; DPE_PROFILE.get_hash_size()],
}

impl SignCmd {
    const IS_SYMMETRIC: u32 = 1 << 31;

    const fn uses_symmetric(&self) -> bool {
        self.flags & Self::IS_SYMMETRIC != 0
    }

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
            .derive_cdi(DPE_PROFILE.alg_len(), &cdi_digest, b"DPE")
            .map_err(|_| DpeErrorCode::CryptoError)?;
        let (priv_key, pub_key) = env
            .crypto
            .derive_key_pair(algs, &cdi, &self.label, b"ECC")
            .map_err(|_| DpeErrorCode::CryptoError)?;

        let sig = env
            .crypto
            .ecdsa_sign_with_derived(algs, digest, &priv_key, pub_key)
            .map_err(|_| DpeErrorCode::CryptoError)?;

        Ok(sig)
    }

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
            .derive_cdi(DPE_PROFILE.alg_len(), &cdi_digest, b"DPE")
            .map_err(|_| DpeErrorCode::CryptoError)?;
        env.crypto
            .hmac_sign_with_derived(algs, &cdi, &self.label, b"HMAC", digest)
            .map_err(|_| DpeErrorCode::CryptoError)
    }
}

impl CommandExecution for SignCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure the operation is supported.
        if !dpe.support.is_symmetric && self.uses_symmetric() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let idx = dpe.get_active_context_pos(&self.handle, locality)?;
        let context = &dpe.contexts[idx];

        if context.context_type == ContextType::Simulation {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let algs = DPE_PROFILE.alg_len();
        let digest = Digest::new(&self.digest, algs).map_err(|_| DpeErrorCode::InternalError)?;

        let EcdsaSig { r, s } = if !self.uses_symmetric() {
            self.ecdsa_sign(dpe, env, idx, &digest)?
        } else {
            let r = self.hmac_sign(dpe, env, idx, &digest)?;
            let s = CryptoBuf::default(algs);
            EcdsaSig { r, s }
        };

        dpe.roll_onetime_use_handle(env, idx)?;

        Ok(Response::Sign(SignResp {
            new_context_handle: dpe.contexts[idx].handle,
            sig_r_or_hmac: r.bytes().try_into().unwrap(),
            sig_s: s.bytes().try_into().unwrap(),
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{
            certify_key::CertifyKeyCmd, tests::TEST_DIGEST, Command, CommandHdr, DeriveChildCmd,
            InitCtxCmd,
        },
        dpe_instance::tests::{TestTypes, SIMULATION_HANDLE, TEST_LOCALITIES},
        support::{test::SUPPORT, Support},
    };
    use crypto::OpensslCrypto;
    use openssl::x509::X509;
    use openssl::{bn::BigNum, ecdsa::EcdsaSig};
    use platform::DefaultPlatform;
    use zerocopy::AsBytes;

    #[cfg(feature = "dpe_profile_p256_sha256")]
    const TEST_LABEL: [u8; DPE_PROFILE.get_hash_size()] = [
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];
    #[cfg(feature = "dpe_profile_p384_sha384")]
    const TEST_LABEL: [u8; DPE_PROFILE.get_hash_size()] = [
        48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26,
        25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];

    const TEST_SIGN_CMD: SignCmd = SignCmd {
        handle: SIMULATION_HANDLE,
        label: TEST_LABEL,
        flags: 0x1234_5678,
        digest: TEST_DIGEST,
    };

    #[test]
    fn test_deserialize_sign() {
        let mut command = CommandHdr::new_for_test(Command::Sign(TEST_SIGN_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_SIGN_CMD.as_bytes());
        assert_eq!(
            Ok(Command::Sign(TEST_SIGN_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_uses_symmetric() {
        // No flags set.
        assert!(!SignCmd {
            flags: 0,
            ..TEST_SIGN_CMD
        }
        .uses_symmetric());

        // Just is-symmetric flag set.
        assert!(SignCmd {
            flags: SignCmd::IS_SYMMETRIC,
            ..TEST_SIGN_CMD
        }
        .uses_symmetric());
    }

    #[test]
    fn test_bad_command_inputs() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT).unwrap();

        // Bad argument
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            SignCmd {
                handle: ContextHandle([0xff; ContextHandle::SIZE]),
                label: TEST_LABEL,
                flags: SignCmd::IS_SYMMETRIC,
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
                flags: 0,
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
                flags: 0,
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        );

        // Simulation contexts should not support the Sign command.
        InitCtxCmd::new_simulation()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, TEST_LOCALITIES[0])
            .is_ok());
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            SignCmd {
                handle: SIMULATION_HANDLE,
                label: TEST_LABEL,
                flags: 0,
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_asymmetric() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, SUPPORT).unwrap();

        for i in 0..3 {
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [i; DPE_PROFILE.get_hash_size()],
                flags: DeriveChildCmd::MAKE_DEFAULT | DeriveChildCmd::INPUT_ALLOW_X509,
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
                flags: 0,
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
                flags: 0,
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
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support {
                auto_init: true,
                is_symmetric: true,
                ..Support::default()
            },
        )
        .unwrap();

        let cmd = SignCmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: SignCmd::IS_SYMMETRIC,
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
            cmd.hmac_sign(
                &mut dpe,
                &mut env,
                idx,
                &Digest::new(&TEST_DIGEST, DPE_PROFILE.alg_len()).unwrap(),
            )
            .unwrap()
            .bytes()
        );
        // Check that s is a buffer of all 0s
        assert!(&resp.sig_s.iter().all(|&b| b == 0x0));
    }
}
