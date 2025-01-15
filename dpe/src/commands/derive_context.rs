// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ActiveContextArgs, Context, ContextHandle, ContextState, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{
        DeriveContextExportedCdiResp, DeriveContextResp, DpeErrorCode, Response, ResponseHdr,
    },
    tci::TciMeasurement,
    x509::{create_exported_dpe_cert, CreateDpeCertArgs, CreateDpeCertResult},
    DPE_PROFILE, MAX_CERT_SIZE,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use cfg_if::cfg_if;

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct DeriveContextFlags(u32);

bitflags! {
    impl DeriveContextFlags: u32 {
        const INTERNAL_INPUT_INFO = 1u32 << 31;
        const INTERNAL_INPUT_DICE = 1u32 << 30;
        const RETAIN_PARENT_CONTEXT = 1u32 << 29;
        const MAKE_DEFAULT = 1u32 << 28;
        const CHANGE_LOCALITY = 1u32 << 27;
        const INPUT_ALLOW_CA = 1u32 << 26;
        const INPUT_ALLOW_X509 = 1u32 << 25;
        const RECURSIVE = 1u32 << 24;
        const EXPORT_CDI = 1u32 << 23;
        const CREATE_CERTIFICATE = 1u32 << 22;
    }
}

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct DeriveContextCmd {
    pub handle: ContextHandle,
    pub data: [u8; DPE_PROFILE.get_hash_size()],
    pub flags: DeriveContextFlags,
    pub tci_type: u32,
    pub target_locality: u32,
}

impl DeriveContextCmd {
    const fn uses_internal_info_input(&self) -> bool {
        self.flags.contains(DeriveContextFlags::INTERNAL_INPUT_INFO)
    }

    const fn uses_internal_dice_input(&self) -> bool {
        self.flags.contains(DeriveContextFlags::INTERNAL_INPUT_DICE)
    }

    pub const fn retains_parent(&self) -> bool {
        self.flags
            .contains(DeriveContextFlags::RETAIN_PARENT_CONTEXT)
    }

    const fn makes_default(&self) -> bool {
        self.flags.contains(DeriveContextFlags::MAKE_DEFAULT)
    }

    pub const fn changes_locality(&self) -> bool {
        self.flags.contains(DeriveContextFlags::CHANGE_LOCALITY)
    }

    const fn allows_ca(&self) -> bool {
        self.flags.contains(DeriveContextFlags::INPUT_ALLOW_CA)
    }

    const fn allows_x509(&self) -> bool {
        self.flags.contains(DeriveContextFlags::INPUT_ALLOW_X509)
    }

    pub const fn is_recursive(&self) -> bool {
        self.flags.contains(DeriveContextFlags::RECURSIVE)
    }

    pub const fn exports_cdi(&self) -> bool {
        self.flags.contains(DeriveContextFlags::EXPORT_CDI)
    }

    pub const fn creates_certificate(&self) -> bool {
        self.flags.contains(DeriveContextFlags::CREATE_CERTIFICATE)
    }

    /// Whether it is okay to make a default context.
    ///
    /// When a default context is in a locality, it MUST be the only context in the locality. This
    /// checks that the operation will result in the locality will only have the newly created
    /// default context and no others.
    ///
    /// # Arguments
    ///
    /// * `parent_idx` - Index of the soon-to-be parent.
    /// * `default_context_idx` - Index of the target locality's default context, if there is one.
    /// * `num_contexts_in_locality` - Number of active contexts already in the locality.
    fn safe_to_make_default(
        &self,
        parent_idx: usize,
        default_context_idx: Option<usize>,
        num_contexts_in_locality: usize,
    ) -> bool {
        match (num_contexts_in_locality, default_context_idx) {
            // No other contexts in the locality.
            (0, None) => true,
            // There is only one context, but that context is the parent.
            (1, Some(default_idx)) if default_idx == parent_idx => {
                // It is okay if the parent is about to be retired. The Child can be the default
                // because the parent is the only other context in the locality and it is about to
                // be retired.
                !self.retains_parent()
            }
            // In all other scenarios, there will be a combination of default and non-default
            // contexts
            _ => false,
        }
    }

    /// Whether it is okay to make a NON-default context.
    ///
    /// There can never be a mixture of default and non-default contexts within the same locality.
    /// This checks to make sure the operation will not result in a mixture.
    ///
    /// # Arguments
    ///
    /// * `parent_idx` - Index of the soon-to-be parent.
    /// * `default_context_idx` - Index of the target locality's default context, if there is one.
    fn safe_to_make_non_default(
        &self,
        parent_idx: usize,
        default_context_idx: Option<usize>,
    ) -> bool {
        match default_context_idx {
            None => true,
            // If the default context is the parent.
            Some(default_idx) if default_idx == parent_idx => {
                // It is okay if the parent is about to be retired.
                !self.retains_parent()
            }
            _ => false,
        }
    }

    /// Whether it is okay to create a child in the given environment.
    ///
    /// When a default context is in a locality, it MUST be the only context in the locality. There
    /// can never be a mixture of default and non-default contexts within the same locality. This
    /// checks that the operation will not violate either statement.
    ///
    /// # Arguments
    ///
    /// * `dpe` - DPE instance executing the command.
    /// * `parent_idx` - Index of the soon-to-be parent.
    /// * `target_locality` - Intended locality of the new child.
    fn safe_to_make_child(
        &self,
        dpe: &mut DpeInstance,
        parent_idx: usize,
        target_locality: u32,
    ) -> Result<bool, DpeErrorCode> {
        let default_context_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), target_locality)
            .ok();

        // count active contexts in target_locality
        let num_contexts_in_locality = dpe.count_contexts(|c: &Context| {
            c.state == ContextState::Active && c.locality == target_locality
        })?;

        Ok(if self.makes_default() {
            self.safe_to_make_default(parent_idx, default_context_idx, num_contexts_in_locality)
        } else {
            self.safe_to_make_non_default(parent_idx, default_context_idx)
        })
    }
}

impl CommandExecution for DeriveContextCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure the operation is supported.
        if (!dpe.support.internal_info() && self.uses_internal_info_input())
            || (!dpe.support.internal_dice() && self.uses_internal_dice_input())
            || (!dpe.support.retain_parent_context() && self.retains_parent())
            || (!dpe.support.x509() && self.allows_x509())
            || (!dpe.support.cdi_export() && (self.creates_certificate() || self.exports_cdi()))
            || (!dpe.support.recursive() && self.is_recursive())
        {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        let parent_idx = dpe.get_active_context_pos(&self.handle, locality)?;
        if (!dpe.contexts[parent_idx].allow_ca() && self.allows_ca())
            || (!dpe.contexts[parent_idx].allow_x509() && self.allows_x509())
            || (self.exports_cdi() && !self.creates_certificate())
            || (self.exports_cdi() && self.is_recursive())
            || (self.exports_cdi() && self.changes_locality())
            || (self.exports_cdi() && self.retains_parent())
            || (self.exports_cdi()
                && dpe.contexts[parent_idx].context_type == ContextType::Simulation)
            || (self.is_recursive() && self.retains_parent())
        {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let target_locality = if !self.changes_locality() {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(!self.changes_locality());
            locality
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(self.changes_locality());
            self.target_locality
        };

        cfg_if! {
            if #[cfg(not(feature = "no-cfi"))] {
                cfi_assert!(dpe.support.internal_info() || !self.uses_internal_info_input());
                cfi_assert!(dpe.support.internal_dice() || !self.uses_internal_dice_input());
                cfi_assert!(dpe.support.retain_parent_context() || !self.retains_parent());
                cfi_assert!(dpe.support.x509() || !self.allows_x509());
                cfi_assert!(dpe.contexts[parent_idx].allow_ca() || !self.allows_ca());
                cfi_assert!(dpe.contexts[parent_idx].allow_x509() || !self.allows_x509());
                cfi_assert!(!self.is_recursive() || !self.retains_parent());
            }
        }

        // Copy the parent context to mutate so that we avoid mutating internal state upon an error.
        let mut tmp_parent_context = dpe.contexts[parent_idx];
        if !self.retains_parent() {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(!self.retains_parent());
            tmp_parent_context.state = ContextState::Retired;
            tmp_parent_context.handle = ContextHandle::new_invalid();
        }

        if self.is_recursive() {
            cfg_if! {
                if #[cfg(not(feature = "disable_recursive"))] {
                    let mut tmp_context = dpe.contexts[parent_idx];
                    if tmp_context.tci.tci_type != self.tci_type {
                        return Err(DpeErrorCode::InvalidArgument);
                    } else {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert_eq(tmp_context.tci.tci_type, self.tci_type);
                    }
                    dpe.add_tci_measurement(
                        env,
                        &mut tmp_context,
                        &TciMeasurement(self.data),
                        target_locality,
                    )?;

                    // Rotate the handle if it isn't the default context.
                    dpe.roll_onetime_use_handle(env, parent_idx)?;

                    dpe.contexts[parent_idx] = Context {
                        handle: dpe.contexts[parent_idx].handle,
                        ..tmp_context
                    };

                    // Return new handle in new_context_handle
                    Ok(Response::DeriveContext(DeriveContextResp {
                        handle: dpe.contexts[parent_idx].handle,
                        // Should be ignored since retain_parent cannot be true
                        parent_handle: ContextHandle::default(),
                        resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
                    }))
                } else {
                    Err(DpeErrorCode::ArgumentNotSupported)?
                }
            }
        } else if self.creates_certificate() && self.exports_cdi() {
            cfg_if! {
                if #[cfg(not(feature = "disable_export_cdi"))] {
                    let args = CreateDpeCertArgs {
                        handle: &self.handle,
                        locality,
                        cdi_label: b"Exported CDI",
                        key_label: b"Exported ECC",
                        context: b"Exported ECC",
                    };
                    let mut cert = [0; MAX_CERT_SIZE];
                    let CreateDpeCertResult { cert_size, exported_cdi_handle, .. } = create_exported_dpe_cert(
                        &args,
                        dpe,
                        env,
                        &mut cert,
                    )?;

                    Ok(Response::DeriveContextExportedCdi(DeriveContextExportedCdiResp {
                        handle: ContextHandle::new_invalid(),
                        parent_handle: ContextHandle::new_invalid(),
                        resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
                        exported_cdi: exported_cdi_handle,
                        certificate_size: cert_size,
                        new_certificate: cert,
                    }))
                } else {
                    Err(DpeErrorCode::ArgumentNotSupported)?
                }
            }
        } else {
            let child_idx = dpe
                .get_next_inactive_context_pos()
                .ok_or(DpeErrorCode::MaxTcis)?;

            let safe_to_make_child = self.safe_to_make_child(dpe, parent_idx, target_locality)?;
            if !safe_to_make_child {
                return Err(DpeErrorCode::InvalidArgument);
            } else {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert!(safe_to_make_child);
            }

            let child_handle = if self.makes_default() {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert!(self.makes_default());
                ContextHandle::default()
            } else {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert!(!self.makes_default());
                dpe.generate_new_handle(env)?
            };

            let allow_ca = self.allows_ca();
            let allow_x509 = self.allows_x509();
            let uses_internal_input_info = self.uses_internal_info_input();
            let uses_internal_input_dice = self.uses_internal_dice_input();

            // Create a temporary context to mutate so that we avoid mutating internal state upon an error.
            let mut tmp_child_context = Context::new();
            tmp_child_context.activate(&ActiveContextArgs {
                context_type: dpe.contexts[parent_idx].context_type,
                locality: target_locality,
                handle: &child_handle,
                tci_type: self.tci_type,
                parent_idx: parent_idx as u8,
                allow_ca,
                allow_x509,
                uses_internal_input_info,
                uses_internal_input_dice,
            });

            dpe.add_tci_measurement(
                env,
                &mut tmp_child_context,
                &TciMeasurement(self.data),
                target_locality,
            )?;

            if self.retains_parent() {
                if !tmp_parent_context.handle.is_default() {
                    tmp_parent_context.handle = dpe.generate_new_handle(env)?;
                } else {
                    cfg_if! {
                        if #[cfg(not(feature = "no-cfi"))] {
                            cfi_assert!(self.retains_parent());
                            cfi_assert!(tmp_parent_context.handle.is_default());
                        }
                    }
                }
            }

            // Add child to the parent's list of children.
            let children_with_child_idx = tmp_parent_context.add_child(child_idx)?;
            tmp_parent_context.children = children_with_child_idx;

            // At this point we cannot error out anymore, so it is safe to set the updated child and parent contexts.
            dpe.contexts[child_idx] = tmp_child_context;
            dpe.contexts[parent_idx] = tmp_parent_context;

            Ok(Response::DeriveContext(DeriveContextResp {
                handle: child_handle,
                parent_handle: dpe.contexts[parent_idx].handle,
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{
            rotate_context::{RotateCtxCmd, RotateCtxFlags},
            tests::{TEST_DIGEST, TEST_LABEL},
            CertifyKeyCmd, CertifyKeyFlags, Command, CommandHdr, InitCtxCmd, SignCmd, SignFlags,
        },
        context::ContextType,
        dpe_instance::tests::{TestTypes, RANDOM_HANDLE, SIMULATION_HANDLE, TEST_LOCALITIES},
        support::Support,
        DpeProfile, MAX_EXPORTED_CDI_SIZE, MAX_HANDLES,
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::{Crypto, Hasher, OpensslCrypto};
    use openssl::{
        bn::BigNum,
        ecdsa::EcdsaSig,
        hash::{Hasher as OpenSSLHasher, MessageDigest},
        x509::X509,
    };
    use platform::{default::DefaultPlatform, Platform, MAX_KEY_IDENTIFIER_SIZE};
    use x509_parser::{nom::Parser, oid_registry::asn1_rs::oid, prelude::*};
    use zerocopy::IntoBytes;

    const TEST_DERIVE_CONTEXT_CMD: DeriveContextCmd = DeriveContextCmd {
        handle: SIMULATION_HANDLE,
        data: TEST_DIGEST,
        flags: DeriveContextFlags(0x1234_5678),
        tci_type: 0x9876_5432,
        target_locality: 0x10CA_1171,
    };

    #[test]
    fn test_deserialize_derive_context() {
        CfiCounter::reset_for_test();
        let mut command = CommandHdr::new_for_test(Command::DERIVE_CONTEXT)
            .as_bytes()
            .to_vec();
        command.extend(TEST_DERIVE_CONTEXT_CMD.as_bytes());
        assert_eq!(
            Ok(Command::DeriveContext(&TEST_DERIVE_CONTEXT_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_support() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT | Support::INTERNAL_INFO | Support::RETAIN_PARENT_CONTEXT,
        )
        .unwrap();

        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::INTERNAL_INPUT_DICE,
                tci_type: 0,
                target_locality: 0
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT | Support::INTERNAL_DICE | Support::RETAIN_PARENT_CONTEXT,
        )
        .unwrap();

        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::INTERNAL_INPUT_INFO,
                tci_type: 0,
                target_locality: 0
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        let mut dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT | Support::INTERNAL_INFO | Support::INTERNAL_DICE,
        )
        .unwrap();

        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
                tci_type: 0,
                target_locality: 0
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_initial_conditions() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::default()).unwrap();

        InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, 0)
            .unwrap();

        // Make sure it can detect wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::empty(),
                tci_type: 0,
                target_locality: 0
            }
            .execute(&mut dpe, &mut env, 1)
        );
    }

    #[test]
    fn test_max_tcis() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        // Fill all contexts with children (minus the auto-init context).
        for _ in 0..MAX_HANDLES - 1 {
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT,
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();
        }

        // Try to create one too many.
        assert_eq!(
            Err(DpeErrorCode::MaxTcis),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::empty(),
                tci_type: 0,
                target_locality: 0
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_set_child_parent_relationship() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        let parent_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::CHANGE_LOCALITY,
            tci_type: 7,
            target_locality: TEST_LOCALITIES[1],
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();
        let child_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[1])
            .unwrap();
        let child = &dpe.contexts[child_idx];

        assert_eq!(parent_idx, child.parent_idx as usize);
        assert_eq!(
            child_idx,
            dpe.contexts[parent_idx].children.trailing_zeros() as usize
        );
        assert_eq!(7, child.tci.tci_type);
        assert_eq!(TEST_LOCALITIES[1], child.locality);
    }

    #[test]
    fn test_set_other_values() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::CHANGE_LOCALITY,
            tci_type: 7,
            target_locality: TEST_LOCALITIES[1],
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let child = &dpe.contexts[dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[1])
            .unwrap()];

        assert_eq!(7, child.tci.tci_type);
        assert_eq!(TEST_LOCALITIES[1], child.locality);
        assert_eq!(ContextType::Normal, child.context_type);
    }

    #[test]
    fn test_correct_child_handle() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        // Make sure child handle is default when creating default child.
        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle([0xff; ContextHandle::SIZE]),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT,
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Make sure child has a random handle when not creating default.
        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: RANDOM_HANDLE,
                parent_handle: ContextHandle([0xff; ContextHandle::SIZE]),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::empty(),
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_full_attestation_flow() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support::INTERNAL_INFO
                | Support::X509
                | Support::AUTO_INIT
                | Support::ROTATE_CONTEXT
                | Support::RETAIN_PARENT_CONTEXT,
        )
        .unwrap();

        let handle = match (RotateCtxCmd {
            handle: ContextHandle::default(),
            flags: RotateCtxFlags::empty(),
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        {
            Ok(Response::RotateCtx(resp)) => resp.handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => Err(e).unwrap(),
        };

        let parent_handle = match (DeriveContextCmd {
            handle,
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        {
            Ok(Response::DeriveContext(resp)) => resp.parent_handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => Err(e).unwrap(),
        };

        let (new_context_handle, sig) = match (SignCmd {
            handle: parent_handle,
            label: TEST_LABEL,
            flags: SignFlags::empty(),
            digest: TEST_DIGEST,
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        {
            Ok(Response::Sign(resp)) => (
                resp.new_context_handle,
                EcdsaSig::from_private_components(
                    BigNum::from_slice(&resp.sig_r).unwrap(),
                    BigNum::from_slice(&resp.sig_s).unwrap(),
                )
                .unwrap(),
            ),
            Ok(_) => panic!("Invalid response type"),
            Err(e) => Err(e).unwrap(),
        };

        let parent_handle = match (DeriveContextCmd {
            handle: new_context_handle,
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
                | DeriveContextFlags::INTERNAL_INPUT_INFO,
            tci_type: 0,
            target_locality: 0,
        })
        .execute(&mut dpe, &mut env, 0)
        {
            Ok(Response::DeriveContext(resp)) => resp.parent_handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => Err(e).unwrap(),
        };

        let ec_pub_key = {
            let cmd = CertifyKeyCmd {
                handle: parent_handle,
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
    fn test_correct_parent_handle() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT | Support::RETAIN_PARENT_CONTEXT,
        )
        .unwrap();

        // Make sure the parent handle is non-sense when not retaining.
        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle([0xff; ContextHandle::SIZE]),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT,
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Make sure the default parent handle stays the default handle when retained.
        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle::default(),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
                    | DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::CHANGE_LOCALITY,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[1],
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // The next test case is to make sure the parent handle rotates when not the default and
        // parent is retained. Right now both localities have a default. We need to mutate one of them so
        // we can create a new child as the default in the locality.
        let old_default_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        dpe.contexts[old_default_idx].handle = ContextHandle([0x1; ContextHandle::SIZE]);

        // Make sure neither the parent nor the child handles are default.
        let Response::DeriveContext(DeriveContextResp {
            handle,
            parent_handle,
            resp_hdr,
            ..
        }) = DeriveContextCmd {
            handle: dpe.contexts[old_default_idx].handle,
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap()
        else {
            panic!("Derive Child Failed");
        };
        assert_eq!(handle, RANDOM_HANDLE);
        assert_eq!(handle, RANDOM_HANDLE);
        assert_ne!(parent_handle, ContextHandle::default());
        assert_eq!(resp_hdr, ResponseHdr::new(DpeErrorCode::NoError));
    }

    #[test]
    fn test_safe_to_make_default() {
        CfiCounter::reset_for_test();
        let mut make_default_in_0 = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement::default().0,
            flags: DeriveContextFlags::MAKE_DEFAULT,
            tci_type: 0,
            target_locality: 0,
        };
        let parent_idx = 0;
        // No default context.
        assert!(make_default_in_0.safe_to_make_default(parent_idx, None, 0));
        // Default context at parent, but not going to retain parent.
        assert!(make_default_in_0.safe_to_make_default(parent_idx, Some(parent_idx), 1));
        // Make default in a different locality that already has a default.
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, Some(1), 1));
        // There is a non-default context already.
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, None, 1));
        // Two non-default contexts.
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, None, 2));
        // This should never be possible, but there is already a mixture of default and non-default
        // contexts.
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, Some(parent_idx), 2));
        // This should never be possible, but there is already a mixture of default and non-default
        // contexts.
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, Some(1), 2));
        // This should never be possible, but there no contexts but somehow the is a default context
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, Some(parent_idx), 0));

        make_default_in_0.flags |= DeriveContextFlags::RETAIN_PARENT_CONTEXT;

        // Retain parent and make default in another locality that doesn't have a default.
        assert!(make_default_in_0.safe_to_make_default(parent_idx, None, 0));
        // Retain default parent and make default in another locality that has a default.
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, Some(1), 1));
        // Retain default parent.
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, Some(parent_idx), 1));
    }

    #[test]
    fn test_safe_to_make_non_default() {
        CfiCounter::reset_for_test();
        let non_default = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement::default().0,
            flags: DeriveContextFlags(0),
            tci_type: 0,
            target_locality: 0,
        };
        let parent_idx = 0;
        // No default context.
        assert!(non_default.safe_to_make_non_default(parent_idx, None));
        // Default context is parent.
        assert!(non_default.safe_to_make_non_default(parent_idx, Some(parent_idx)));
        // Default context is not parent.
        assert!(!non_default.safe_to_make_non_default(parent_idx, Some(1)));
    }

    #[test]
    fn test_default_context_cannot_be_retained() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT | Support::RETAIN_PARENT_CONTEXT,
        )
        .unwrap();

        assert_eq!(
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: TciMeasurement::default().0,
                flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
            Err(DpeErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn test_make_default_in_other_locality_that_has_non_default() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT | Support::RETAIN_PARENT_CONTEXT,
        )
        .unwrap();

        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
                | DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::CHANGE_LOCALITY,
            tci_type: 7,
            target_locality: TEST_LOCALITIES[1],
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        assert_eq!(
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
                    | DeriveContextFlags::CHANGE_LOCALITY,
                tci_type: 7,
                target_locality: TEST_LOCALITIES[1],
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
            Err(DpeErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn test_recursive() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT
                | Support::RECURSIVE
                | Support::INTERNAL_DICE
                | Support::INTERNAL_INFO,
        )
        .unwrap();

        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle::default(),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [1; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::RECURSIVE
                    | DeriveContextFlags::INTERNAL_INPUT_INFO
                    | DeriveContextFlags::INTERNAL_INPUT_DICE,
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [2; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::RECURSIVE
                | DeriveContextFlags::INTERNAL_INPUT_INFO
                | DeriveContextFlags::INTERNAL_INPUT_DICE,
            tci_type: 0,
            target_locality: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let child_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), 0)
            .unwrap();
        // ensure flags are unchanged
        assert!(dpe.contexts[child_idx].allow_ca());
        assert!(dpe.contexts[child_idx].allow_x509());
        assert!(!dpe.contexts[child_idx].uses_internal_input_info());
        assert!(!dpe.contexts[child_idx].uses_internal_input_dice());

        // check tci_cumulative correctly computed
        let mut hasher = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        hasher.update(&[0u8; DPE_PROFILE.get_hash_size()]).unwrap();
        hasher.update(&[1u8; DPE_PROFILE.get_hash_size()]).unwrap();
        let temp_digest = hasher.finish().unwrap();
        let mut hasher_2 = env.crypto.hash_initialize(DPE_PROFILE.alg_len()).unwrap();
        hasher_2.update(temp_digest.bytes()).unwrap();
        hasher_2
            .update(&[2u8; DPE_PROFILE.get_hash_size()])
            .unwrap();
        let digest = hasher_2.finish().unwrap();
        assert_eq!(digest.bytes(), dpe.contexts[child_idx].tci.tci_cumulative.0);
    }

    #[test]
    fn test_cdi_export_flags() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT
                | Support::CDI_EXPORT
                | Support::X509
                | Support::RECURSIVE
                | Support::SIMULATION
                | Support::RETAIN_PARENT_CONTEXT,
        )
        .unwrap();

        // When `DeriveContextFlags::EXPORT_CDI` is set, `DeriveContextFlags::CREATE_CERTIFICATE` MUST
        // also be set, or `DpeErrorCode::InvalidArgument` is raised.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CHANGE_LOCALITY,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[1]
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::RECURSIVE,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0]
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // `DeriveContextFlags::EXPORT_CDI` cannot be set with `DeriveContextFlags::RETAIN_PARENT_CONTEXT`
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0]
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        let simulation_handle = match InitCtxCmd::new_simulation()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::InitCtx(resp) => resp.handle,
            _ => panic!("Wrong response type."),
        };
        // DPE must return an `DpeErrorCode::InvalidArgument` error if the context-handle refers to a simulation context.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            DeriveContextCmd {
                handle: simulation_handle,
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::CREATE_CERTIFICATE | DeriveContextFlags::EXPORT_CDI,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0]
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // DPE must return an `DpeErrorCode::InvalidArgument` if `DeriveContextFlags::EXPORT_CDI` and `DeriveContextFlags::RECURSIVE` are set.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::CREATE_CERTIFICATE
                    | DeriveContextFlags::EXPORT_CDI
                    | DeriveContextFlags::RECURSIVE,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0]
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT | Support::CDI_EXPORT | Support::X509,
        )
        .unwrap();

        // Happy case!
        let res = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]);

        let res = match res {
            Ok(Response::DeriveContextExportedCdi(res)) => res,
            _ => panic!("expected to get a valid DeriveContextExportedCdi response."),
        };
        assert_eq!(res.parent_handle, ContextHandle::new_invalid());
        assert_eq!(res.handle, ContextHandle::new_invalid());
        assert_ne!(res.certificate_size, 0);
        assert_ne!(res.new_certificate, [0; MAX_CERT_SIZE]);
        assert_ne!(res.exported_cdi, [0; MAX_EXPORTED_CDI_SIZE]);

        let mut dpe = DpeInstance::new(
            &mut env,
            Support::AUTO_INIT | Support::INTERNAL_INFO | Support::INTERNAL_DICE | Support::X509,
        )
        .unwrap();

        // `DpeInstance` needs `Support::EXPORT_CDI` to use `DeriveContextFlags::EXPORT_CDI`.
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::CREATE_CERTIFICATE | DeriveContextFlags::EXPORT_CDI,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0]
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // `DpeInstance` needs `Support::EXPORT_CDI` to use `DeriveContextFlags::EXPORT_CDI`.
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0]
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // `DpeInstance` needs `Support::EXPORT_CDI` to use `DeriveContextFlags::EXPORT_CDI`.
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveContextFlags::CREATE_CERTIFICATE,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0]
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }
    #[test]
    fn test_create_ca() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::X509 | Support::CDI_EXPORT).unwrap();
        let init_resp = match InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::InitCtx(resp) => resp,
            _ => panic!("Incorrect return type."),
        };
        let derive_cmd = DeriveContextCmd {
            handle: init_resp.handle,
            flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
            data: [0; DPE_PROFILE.get_tci_size()],
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
        };
        let derive_resp = match derive_cmd
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap()
        {
            Response::DeriveContextExportedCdi(resp) => resp,
            _ => panic!("Wrong response type."),
        };
        assert_eq!(ContextHandle::new_invalid(), derive_resp.handle);
        assert_eq!(ContextHandle::new_invalid(), derive_resp.parent_handle);
        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        match parser
            .parse(&derive_resp.new_certificate[..derive_resp.certificate_size.try_into().unwrap()])
        {
            Ok((_, cert)) => {
                match cert.basic_constraints() {
                    Ok(Some(basic_constraints)) => {
                        assert!(basic_constraints.value.ca);
                    }
                    Ok(None) => panic!("basic constraints extension not found"),
                    Err(_) => panic!("multiple basic constraints extensions found"),
                }
                let pub_key = &cert.tbs_certificate.subject_pki.subject_public_key.data;
                let mut hasher = match DPE_PROFILE {
                    DpeProfile::P256Sha256 => OpenSSLHasher::new(MessageDigest::sha256()).unwrap(),
                    DpeProfile::P384Sha384 => OpenSSLHasher::new(MessageDigest::sha384()).unwrap(),
                };
                hasher.update(pub_key).unwrap();
                let expected_ski: &[u8] = &hasher.finish().unwrap();
                match cert.get_extension_unique(&oid!(2.5.29 .14)) {
                    Ok(Some(subject_key_identifier_ext)) => {
                        if let ParsedExtension::SubjectKeyIdentifier(key_identifier) =
                            subject_key_identifier_ext.parsed_extension()
                        {
                            assert_eq!(key_identifier.0, &expected_ski[..MAX_KEY_IDENTIFIER_SIZE]);
                        } else {
                            panic!("Extension has wrong type");
                        }
                    }
                    Ok(None) => panic!("subject key identifier extension not found"),
                    Err(_) => panic!("multiple subject key identifier extensions found"),
                }
                let mut expected_aki = [0u8; MAX_KEY_IDENTIFIER_SIZE];
                env.platform
                    .get_issuer_key_identifier(&mut expected_aki)
                    .unwrap();
                match cert.get_extension_unique(&oid!(2.5.29 .35)) {
                    Ok(Some(extension)) => {
                        if let ParsedExtension::AuthorityKeyIdentifier(aki) =
                            extension.parsed_extension()
                        {
                            let key_identifier = aki.key_identifier.clone().unwrap();
                            assert_eq!(&key_identifier.0, &expected_aki,);
                        } else {
                            panic!("Extension has wrong type");
                        }
                    }
                    Ok(None) => panic!("authority key identifier extension not found"),
                    Err(_) => panic!("multiple authority key identifier extensions found"),
                }
            }
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };
    }
}
