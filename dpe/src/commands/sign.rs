// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ContextHandle, ContextType},
    dpe_instance::DpeInstance,
    response::{DpeErrorCode, Response, ResponseHdr, SignResp},
    DPE_PROFILE,
};
use crypto::{Crypto, CryptoBuf, Digest, EcdsaSig, HmacSig};
use platform::Platform;

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

    fn ecdsa_sign<C: Crypto, P: Platform>(
        &self,
        dpe: &mut DpeInstance<C, P>,
        idx: usize,
        digest: &Digest,
        crypto: &mut C,
    ) -> Result<EcdsaSig, DpeErrorCode> {
        let algs = DPE_PROFILE.alg_len();
        let cdi = dpe.derive_cdi(idx, crypto)?;
        let priv_key = crypto
            .derive_private_key(algs, &cdi, &self.label, b"ECC")
            .map_err(|_| DpeErrorCode::CryptoError)?;

        let sig = crypto
            .ecdsa_sign_with_derived(algs, digest, &priv_key)
            .map_err(|_| DpeErrorCode::CryptoError)?;

        Ok(sig)
    }

    fn hmac_sign<C: Crypto, P: Platform>(
        &self,
        dpe: &mut DpeInstance<C, P>,
        idx: usize,
        digest: &Digest,
        crypto: &mut C,
    ) -> Result<HmacSig, DpeErrorCode> {
        let algs = DPE_PROFILE.alg_len();
        let cdi = dpe.derive_cdi(idx, crypto)?;
        crypto
            .hmac_sign_with_derived(algs, &cdi, &self.label, b"HMAC", digest)
            .map_err(|_| DpeErrorCode::CryptoError)
    }
}

impl<C: Crypto, P: Platform> CommandExecution<C, P> for SignCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance<C, P>,
        locality: u32,
        crypto: &mut C,
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
            self.ecdsa_sign(dpe, idx, &digest, crypto)?
        } else {
            let r = self.hmac_sign(dpe, idx, &digest, crypto)?;
            let s = CryptoBuf::default(algs);
            EcdsaSig { r, s }
        };

        dpe.roll_onetime_use_handle(idx, crypto)?;

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
        dpe_instance::tests::{SIMULATION_HANDLE, TEST_LOCALITIES},
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
        let mut crypto = OpensslCrypto::new();
        let mut dpe =
            DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(SUPPORT, &mut crypto)
                .unwrap();

        // Bad argument
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            SignCmd {
                handle: ContextHandle([0xff; ContextHandle::SIZE]),
                label: TEST_LABEL,
                flags: SignCmd::IS_SYMMETRIC,
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, TEST_LOCALITIES[0], &mut crypto)
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
            .execute(&mut dpe, TEST_LOCALITIES[0], &mut crypto)
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
            .execute(&mut dpe, TEST_LOCALITIES[1], &mut crypto)
        );

        // Simulation contexts should not support the Sign command.
        InitCtxCmd::new_simulation()
            .execute(&mut dpe, TEST_LOCALITIES[0], &mut crypto)
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
            .execute(&mut dpe, TEST_LOCALITIES[0], &mut crypto)
        );
    }

    #[test]
    fn test_asymmetric() {
        let mut crypto = OpensslCrypto::new();
        let mut dpe =
            DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(SUPPORT, &mut crypto)
                .unwrap();

        for i in 0..3 {
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [i; DPE_PROFILE.get_hash_size()],
                flags: DeriveChildCmd::MAKE_DEFAULT | DeriveChildCmd::INPUT_ALLOW_X509,
                tci_type: i as u32,
                target_locality: 0,
            }
            .execute(&mut dpe, TEST_LOCALITIES[0], &mut crypto)
            .unwrap();
        }

        let sig = {
            let cmd = SignCmd {
                handle: ContextHandle::default(),
                label: TEST_LABEL,
                flags: 0,
                digest: TEST_DIGEST,
            };
            let resp = match cmd
                .execute(&mut dpe, TEST_LOCALITIES[0], &mut crypto)
                .unwrap()
            {
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
            let certify_resp = match cmd
                .execute(&mut dpe, TEST_LOCALITIES[0], &mut crypto)
                .unwrap()
            {
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
        let mut crypto = OpensslCrypto::new();
        let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(
            Support {
                auto_init: true,
                is_symmetric: true,
                ..Support::default()
            },
            &mut crypto,
        )
        .unwrap();

        let cmd = SignCmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: SignCmd::IS_SYMMETRIC,
            digest: TEST_DIGEST,
        };
        let resp = match cmd
            .execute(&mut dpe, TEST_LOCALITIES[0], &mut crypto)
            .unwrap()
        {
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
                idx,
                &Digest::new(&TEST_DIGEST, DPE_PROFILE.alg_len()).unwrap(),
                &mut crypto,
            )
            .unwrap()
            .bytes()
        );
        // Check that s is a buffer of all 0s
        assert!(&resp.sig_s.iter().all(|&b| b == 0x0));
    }
}
