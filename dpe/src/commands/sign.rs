// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ContextHandle, ContextType},
    dpe_instance::DpeInstance,
    response::{DpeErrorCode, Response, SignResp},
    DPE_PROFILE,
};
use core::mem::size_of;
use crypto::{Crypto, Digest, EcdsaSig};

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
pub struct SignCmd {
    handle: ContextHandle,
    label: [u8; DPE_PROFILE.get_hash_size()],
    flags: u32,
    digest: [u8; DPE_PROFILE.get_hash_size()],
}

impl SignCmd {
    const _IS_SYMMETRIC: u32 = 1 << 31;
    const _ND_DERIVATION: u32 = 1 << 30;

    const fn _uses_symmetric(&self) -> bool {
        self.flags & Self::_IS_SYMMETRIC != 0
    }

    /// Uses non-deterministic derivation. If symmetric algorithms are used, this flag is ignored.
    const fn _uses_nd_derivation(&self) -> bool {
        !self._uses_symmetric() && self.flags & Self::_ND_DERIVATION != 0
    }
}

impl TryFrom<&[u8]> for SignCmd {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<SignCmd>() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let mut offset = 0;

        let handle = ContextHandle::try_from(raw)?;
        offset += ContextHandle::SIZE;

        let label = raw[offset..offset + DPE_PROFILE.get_hash_size()]
            .try_into()
            .unwrap();
        offset += DPE_PROFILE.get_hash_size();
        let flags = u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap());
        offset += size_of::<u32>();
        let digest = raw[offset..offset + DPE_PROFILE.get_hash_size()]
            .try_into()
            .unwrap();

        Ok(SignCmd {
            handle,
            label,
            flags,
            digest,
        })
    }
}

impl<C: Crypto> CommandExecution<C> for SignCmd {
    fn execute(&self, dpe: &mut DpeInstance<C>, locality: u32) -> Result<Response, DpeErrorCode> {
        let idx = dpe
            .get_active_context_pos(&self.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;
        let context = &dpe.contexts[idx];

        if context.locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }
        if context.context_type == ContextType::Simulation {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let cdi = dpe.derive_cdi(idx)?;
        let digest = Digest::new(&self.digest, DPE_PROFILE.alg_len())
            .map_err(|_| DpeErrorCode::InternalError)?;
        let EcdsaSig { r, s } =
            C::ecdsa_sign_with_derived(DPE_PROFILE.alg_len(), &cdi, &self.label, b"ECC", &digest)
                .map_err(|_| DpeErrorCode::InternalError)?;

        dpe.roll_onetime_use_handle(idx)?;

        Ok(Response::Sign(SignResp {
            new_context_handle: dpe.contexts[idx].handle,
            sig_r_or_hmac: r.bytes().try_into().unwrap(),
            sig_s: s.bytes().try_into().unwrap(),
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
        support::test::SUPPORT,
    };
    use crypto::OpensslCrypto;
    use openssl::x509::X509;
    use openssl::{bn::BigNum, ecdsa::EcdsaSig};
    use zerocopy::{AsBytes, FromBytes};

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
    fn try_from_sign() {
        let command_bytes = TEST_SIGN_CMD.as_bytes();
        assert_eq!(
            SignCmd::read_from_prefix(command_bytes).unwrap(),
            SignCmd::try_from(command_bytes).unwrap(),
        );
    }

    #[test]
    fn test_deserialize_sign() {
        let mut command = CommandHdr::new(Command::Sign(TEST_SIGN_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_SIGN_CMD.as_bytes());
        assert_eq!(
            Ok(Command::Sign(TEST_SIGN_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_slice_to_sign() {
        // Test if too small.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            SignCmd::try_from([0u8; size_of::<SignCmd>() - 1].as_slice())
        );

        assert_eq!(
            TEST_SIGN_CMD,
            SignCmd::try_from(TEST_SIGN_CMD.as_bytes()).unwrap()
        );
    }

    #[test]
    fn test_uses_nd_derivation() {
        // No flags set.
        assert!(!SignCmd {
            flags: 0,
            ..TEST_SIGN_CMD
        }
        ._uses_nd_derivation());

        // Other flag set.
        assert!(!SignCmd {
            flags: SignCmd::_IS_SYMMETRIC,
            ..TEST_SIGN_CMD
        }
        ._uses_nd_derivation());

        // Just non-deterministic flag set.
        assert!(SignCmd {
            flags: SignCmd::_ND_DERIVATION,
            ..TEST_SIGN_CMD
        }
        ._uses_nd_derivation());

        // If both are set, it ignores non-deterministic derivation.
        assert!(!SignCmd {
            flags: SignCmd::_IS_SYMMETRIC | SignCmd::_ND_DERIVATION,
            ..TEST_SIGN_CMD
        }
        ._uses_nd_derivation());
    }

    #[test]
    fn test_bad_command_inputs() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new_for_test(SUPPORT, &TEST_LOCALITIES).unwrap();

        // Bad handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            SignCmd {
                handle: ContextHandle([0xff; ContextHandle::SIZE]),
                label: TEST_LABEL,
                flags: 0,
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Wrong locality.
        assert!(dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .is_some());
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            SignCmd {
                handle: ContextHandle::default(),
                label: TEST_LABEL,
                flags: 0,
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, TEST_LOCALITIES[1])
        );

        // Simulation contexts should not support the Sign command.
        InitCtxCmd::new_simulation()
            .execute(&mut dpe, TEST_LOCALITIES[0])
            .unwrap();
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, TEST_LOCALITIES[0])
            .is_some());
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            SignCmd {
                handle: SIMULATION_HANDLE,
                label: TEST_LABEL,
                flags: 0,
                digest: TEST_DIGEST
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_asymmetric_deterministic() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new_for_test(SUPPORT, &TEST_LOCALITIES).unwrap();

        for i in 0..3 {
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [i; DPE_PROFILE.get_hash_size()],
                flags: DeriveChildCmd::MAKE_DEFAULT,
                tci_type: i as u32,
                target_locality: 0,
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
            .unwrap();
        }

        let sig = {
            let cmd = SignCmd {
                handle: ContextHandle::default(),
                label: TEST_LABEL,
                flags: 0,
                digest: TEST_DIGEST,
            };
            let resp = match cmd.execute(&mut dpe, TEST_LOCALITIES[0]).unwrap() {
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
            };
            let certify_resp = match cmd.execute(&mut dpe, TEST_LOCALITIES[0]).unwrap() {
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
