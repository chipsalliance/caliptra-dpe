// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    commands::destroy_context,
    context::{ActiveContextArgs, Context, ContextHandle, ContextState, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DeriveContextExportedCdiResp, DeriveContextResp, DpeErrorCode, Response},
    tci::TciMeasurement,
    x509::{create_exported_dpe_cert, CreateDpeCertArgs, CreateDpeCertResult},
    DpeFlags, State, DPE_PROFILE, MAX_CERT_SIZE,
};
use bitflags::bitflags;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use cfg_if::cfg_if;

use platform::Platform;

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
pub struct DeriveContextFlags(pub u32);

bitflags! {
    impl DeriveContextFlags: u32 {
        const INTERNAL_INPUT_INFO = 1u32 << 31;
        const INTERNAL_INPUT_DICE = 1u32 << 30;
        const RETAIN_PARENT_CONTEXT = 1u32 << 29;
        const MAKE_DEFAULT = 1u32 << 28;
        const CHANGE_LOCALITY = 1u32 << 27;
        const ALLOW_NEW_CONTEXT_TO_EXPORT = 1u32 << 26;
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
    pub data: [u8; DPE_PROFILE.hash_size()],
    pub flags: DeriveContextFlags,
    pub tci_type: u32,
    pub target_locality: u32,
    pub svn: u32,
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

    pub const fn allows_new_context_to_export(&self) -> bool {
        self.flags
            .contains(DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT)
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
        state: &State,
        parent_idx: usize,
        target_locality: u32,
    ) -> Result<bool, DpeErrorCode> {
        let default_context_idx = state
            .get_active_context_pos(&ContextHandle::default(), target_locality)
            .ok();

        // count active contexts in target_locality
        let num_contexts_in_locality = state.count_contexts(|c: &Context| {
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
        let support = env.state.support;
        // Make sure the operation is supported.
        if (!support.internal_info() && self.uses_internal_info_input())
            || (!support.internal_dice() && self.uses_internal_dice_input())
            || (!support.retain_parent_context() && self.retains_parent())
            || (!support.x509() && self.allows_x509())
            || (!support.cdi_export() && (self.creates_certificate() || self.exports_cdi()))
            || (!support.recursive() && self.is_recursive())
        {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        let parent_idx = env.state.get_active_context_pos(&self.handle, locality)?;
        if (!env.state.contexts[parent_idx].allow_x509() && self.allows_x509())
            || (self.exports_cdi() && !self.creates_certificate())
            || (self.exports_cdi() && self.is_recursive())
            || (self.exports_cdi() && self.changes_locality())
            || (self.exports_cdi()
                && env.state.contexts[parent_idx].context_type == ContextType::Simulation)
            || (self.exports_cdi() && !env.state.contexts[parent_idx].allow_export_cdi())
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
                cfi_assert!(support.internal_info() || !self.uses_internal_info_input());
                cfi_assert!(support.internal_dice() || !self.uses_internal_dice_input());
                cfi_assert!(support.retain_parent_context() || !self.retains_parent());
                cfi_assert!(support.x509() || !self.allows_x509());
                cfi_assert!(env.state.contexts[parent_idx].allow_x509() || !self.allows_x509());
                cfi_assert!(!self.is_recursive() || !self.retains_parent());
            }
        }

        if self.is_recursive() {
            cfg_if! {
                if #[cfg(not(feature = "disable_recursive"))] {
                    let mut tmp_context = env.state.contexts[parent_idx];
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

                    env.state.contexts[parent_idx] = Context {
                        handle: env.state.contexts[parent_idx].handle,
                        ..tmp_context
                    };

                    // Return new handle in new_context_handle
                    return Ok(Response::DeriveContext(DeriveContextResp {
                        handle: env.state.contexts[parent_idx].handle,
                        // Should be ignored since retain_parent cannot be true
                        parent_handle: ContextHandle::default(),
                        resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
                    }));
                } else {
                    Err(DpeErrorCode::ArgumentNotSupported)?
                }
            }
        }

        // Copy the parent context to mutate so that we avoid mutating internal state upon an error.
        let mut tmp_parent_context = env.state.contexts[parent_idx];
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
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(!self.retains_parent());
            tmp_parent_context.state = ContextState::Retired;
            tmp_parent_context.handle = ContextHandle::new_invalid();
        }

        if self.creates_certificate() && self.exports_cdi() {
            cfg_if! {
                if #[cfg(not(feature = "disable_export_cdi"))] {
                    let ueid = &env.platform.get_ueid()?;
                    let ueid = ueid.get()?;
                    let args = CreateDpeCertArgs {
                        handle: &self.handle,
                        locality,
                        cdi_label: b"Exported CDI",
                        key_label: b"Exported ECC",
                        context: b"Exported ECC",
                        ueid,
                        dice_extensions_are_critical: env.state.flags.contains(DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL),
                    };
                    let mut cert = [0; MAX_CERT_SIZE];
                    let CreateDpeCertResult { cert_size, exported_cdi_handle, .. } = create_exported_dpe_cert(
                        &args,
                        dpe,
                        env,
                        &mut cert,
                    )?;

                    if !self.retains_parent() && !env.state.contexts[parent_idx].has_children() {
                        // When the parent is not retained and there are no other children,
                        // destroy it.
                        destroy_context::destroy_context(&self.handle, env.state, locality)?;
                    } else {
                        // We either retained the parent or it has other children, so retire it and
                        // make it's handle invalid.
                        // At this point we cannot error out anymore, so it is safe to set the parent context.
                        env.state.contexts[parent_idx] = tmp_parent_context;
                    }


                    return Ok(Response::DeriveContextExportedCdi(DeriveContextExportedCdiResp {
                        handle: ContextHandle::new_invalid(),
                        parent_handle: env.state.contexts[parent_idx].handle,
                        resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
                        exported_cdi: exported_cdi_handle,
                        certificate_size: cert_size,
                        new_certificate: cert,
                    }))
                } else {
                    Err(DpeErrorCode::ArgumentNotSupported)?
                }
            }
        }

        let child_idx = env
            .state
            .get_next_inactive_context_pos()
            .ok_or(DpeErrorCode::MaxTcis)?;

        let safe_to_make_child = self.safe_to_make_child(env.state, parent_idx, target_locality)?;
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

        let allow_x509 = self.allows_x509();
        let uses_internal_input_info = self.uses_internal_info_input();
        let uses_internal_input_dice = self.uses_internal_dice_input();

        // Create a temporary context to mutate so that we avoid mutating internal state upon an error.
        let mut tmp_child_context = Context::new();
        tmp_child_context.activate(&ActiveContextArgs {
            context_type: env.state.contexts[parent_idx].context_type,
            locality: target_locality,
            handle: &child_handle,
            tci_type: self.tci_type,
            parent_idx: parent_idx as u8,
            allow_x509,
            uses_internal_input_info,
            uses_internal_input_dice,
            allow_export_cdi: self.allows_new_context_to_export()
                & tmp_parent_context.allow_export_cdi(),
            svn: self.svn,
        });

        dpe.add_tci_measurement(
            env,
            &mut tmp_child_context,
            &TciMeasurement(self.data),
            target_locality,
        )?;

        // Add child to the parent's list of children.
        let children_with_child_idx = tmp_parent_context.add_child(child_idx)?;
        tmp_parent_context.children = children_with_child_idx;

        // At this point we cannot error out anymore, so it is safe to set the updated child and parent contexts.
        env.state.contexts[child_idx] = tmp_child_context;
        env.state.contexts[parent_idx] = tmp_parent_context;

        Ok(Response::DeriveContext(DeriveContextResp {
            handle: child_handle,
            parent_handle: env.state.contexts[parent_idx].handle,
            resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{
            rotate_context::{RotateCtxCmd, RotateCtxFlags},
            tests::{PROFILES, TEST_DIGEST, TEST_LABEL},
            CertifyKeyCmd, CertifyKeyFlags, Command, CommandHdr, InitCtxCmd, SignCmd, SignFlags,
        },
        context::ContextType,
        dpe_instance::tests::{
            test_env, TestTypes, RANDOM_HANDLE, SIMULATION_HANDLE, TEST_LOCALITIES,
        },
        response::NewHandleResp,
        support::Support,
        validation::DpeValidator,
        DpeProfile, MAX_EXPORTED_CDI_SIZE, MAX_HANDLES,
    };
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::{Crypto, Hasher};
    use openssl::{
        bn::BigNum,
        ecdsa::EcdsaSig,
        hash::{Hasher as OpenSSLHasher, MessageDigest},
        x509::X509,
    };
    use platform::{Platform, MAX_KEY_IDENTIFIER_SIZE};
    use x509_parser::{nom::Parser, oid_registry::asn1_rs::oid, prelude::*};
    use zerocopy::IntoBytes;

    const TEST_DERIVE_CONTEXT_CMD: DeriveContextCmd = DeriveContextCmd {
        handle: SIMULATION_HANDLE,
        data: TEST_DIGEST,
        flags: DeriveContextFlags(0x1234_5678),
        tci_type: 0x9876_5432,
        target_locality: 0x10CA_1171,
        svn: 0,
    };

    #[test]
    fn test_deserialize_derive_context() {
        CfiCounter::reset_for_test();
        for p in PROFILES {
            let mut command = CommandHdr::new(p, Command::DERIVE_CONTEXT)
                .as_bytes()
                .to_vec();
            command.extend(TEST_DERIVE_CONTEXT_CMD.as_bytes());
            assert_eq!(
                Ok(Command::DeriveContext(&TEST_DERIVE_CONTEXT_CMD)),
                Command::deserialize(p, &command)
            );
        }
    }

    #[test]
    fn test_support() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::AUTO_INIT | Support::INTERNAL_INFO | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::INTERNAL_INPUT_DICE,
                tci_type: 0,
                target_locality: 0,
                svn: 0
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        *env.state = State::new(
            Support::AUTO_INIT | Support::INTERNAL_DICE | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        dpe = DpeInstance::new(&mut env).unwrap();

        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::INTERNAL_INPUT_INFO,
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        *env.state = State::new(
            Support::AUTO_INIT | Support::INTERNAL_INFO | Support::INTERNAL_DICE,
            DpeFlags::empty(),
        );
        dpe = DpeInstance::new(&mut env).unwrap();

        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_initial_conditions() {
        CfiCounter::reset_for_test();
        let mut state = State::default();
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        InitCtxCmd::new_use_default()
            .execute(&mut dpe, &mut env, 0)
            .unwrap();

        // Make sure it can detect wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::empty(),
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, 1)
        );
    }

    #[test]
    fn test_max_tcis() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        // Fill all contexts with children (minus the auto-init context).
        for _ in 0..MAX_HANDLES - 1 {
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT,
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();
        }

        // Try to create one too many.
        assert_eq!(
            Err(DpeErrorCode::MaxTcis),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::empty(),
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_set_child_parent_relationship() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        let parent_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::CHANGE_LOCALITY,
            tci_type: 7,
            target_locality: TEST_LOCALITIES[1],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();
        let child_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[1])
            .unwrap();
        let child = &env.state.contexts[child_idx];

        assert_eq!(parent_idx, child.parent_idx as usize);
        assert_eq!(
            child_idx,
            env.state.contexts[parent_idx].children.trailing_zeros() as usize
        );
        assert_eq!(7, child.tci.tci_type);
        assert_eq!(TEST_LOCALITIES[1], child.locality);
    }

    #[test]
    fn test_set_other_values() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::CHANGE_LOCALITY,
            tci_type: 7,
            target_locality: TEST_LOCALITIES[1],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let child = &env.state.contexts[env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[1])
            .unwrap()];

        assert_eq!(7, child.tci.tci_type);
        assert_eq!(TEST_LOCALITIES[1], child.locality);
        assert_eq!(ContextType::Normal, child.context_type);
    }

    #[test]
    fn test_correct_child_handle() {
        CfiCounter::reset_for_test();
        let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        // Make sure child handle is default when creating default child.
        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle([0xff; ContextHandle::SIZE]),
                resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT,
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Make sure child has a random handle when not creating default.
        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: RANDOM_HANDLE,
                parent_handle: ContextHandle([0xff; ContextHandle::SIZE]),
                resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::empty(),
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_full_attestation_flow() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::INTERNAL_INFO
                | Support::X509
                | Support::AUTO_INIT
                | Support::ROTATE_CONTEXT
                | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        let handle = match (RotateCtxCmd {
            handle: ContextHandle::default(),
            flags: RotateCtxFlags::empty(),
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        {
            Ok(Response::RotateCtx(resp)) => resp.handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => panic!("{:?}", e),
        };

        let parent_handle = match (DeriveContextCmd {
            handle,
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        {
            Ok(Response::DeriveContext(resp)) => resp.parent_handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => panic!("{:?}", e),
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
            Err(e) => panic!("{:?}", e),
        };

        let parent_handle = match (DeriveContextCmd {
            handle: new_context_handle,
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
                | DeriveContextFlags::INTERNAL_INPUT_INFO,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
        })
        .execute(&mut dpe, &mut env, 0)
        {
            Ok(Response::DeriveContext(resp)) => resp.parent_handle,
            Ok(_) => panic!("Invalid response type"),
            Err(e) => panic!("{:?}", e),
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
        let mut state = State::new(
            Support::AUTO_INIT | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        // Make sure the parent handle is non-sense when not retaining.
        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle([0xff; ContextHandle::SIZE]),
                resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT,
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Make sure the default parent handle stays the default handle when retained.
        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle::default(),
                resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
                    | DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::CHANGE_LOCALITY,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[1],
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // The next test case is to make sure the parent handle rotates when not the default and
        // parent is retained. Right now both localities have a default. We need to mutate one of them so
        // we can create a new child as the default in the locality.
        let old_default_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        env.state.contexts[old_default_idx].handle = ContextHandle([0x1; ContextHandle::SIZE]);

        // Make sure neither the parent nor the child handles are default.
        let Response::DeriveContext(DeriveContextResp {
            handle,
            parent_handle,
            resp_hdr,
            ..
        }) = DeriveContextCmd {
            handle: env.state.contexts[old_default_idx].handle,
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap()
        else {
            panic!("Derive Child Failed");
        };

        let next_random_handle = ContextHandle([
            112, 83, 173, 43, 197, 57, 135, 119, 186, 3, 155, 37, 142, 89, 173, 157,
        ]);

        // parent_handle is the first rotated handle, so it gets the RANDOM_HANDLE.
        assert_eq!(parent_handle, RANDOM_HANDLE);
        assert_eq!(handle, next_random_handle);
        assert_ne!(parent_handle, ContextHandle::default());
        assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
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
            svn: 0,
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
            svn: 0,
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
        let mut state = State::new(
            Support::AUTO_INIT | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        assert_eq!(
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: TciMeasurement::default().0,
                flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
            Err(DpeErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn test_make_default_in_other_locality_that_has_non_default() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::AUTO_INIT | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
                | DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::CHANGE_LOCALITY,
            tci_type: 7,
            target_locality: TEST_LOCALITIES[1],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        assert_eq!(
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
                    | DeriveContextFlags::CHANGE_LOCALITY,
                tci_type: 7,
                target_locality: TEST_LOCALITIES[1],
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
            Err(DpeErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn test_recursive() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::AUTO_INIT
                | Support::RECURSIVE
                | Support::INTERNAL_DICE
                | Support::INTERNAL_INFO,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        assert_eq!(
            Ok(Response::DeriveContext(DeriveContextResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle::default(),
                resp_hdr: dpe.response_hdr(DpeErrorCode::NoError),
            })),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [1; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::RECURSIVE
                    | DeriveContextFlags::INTERNAL_INPUT_INFO
                    | DeriveContextFlags::INTERNAL_INPUT_DICE,
                tci_type: 0,
                target_locality: 0,
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [2; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::RECURSIVE
                | DeriveContextFlags::INTERNAL_INPUT_INFO
                | DeriveContextFlags::INTERNAL_INPUT_DICE,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        let child_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), 0)
            .unwrap();
        // ensure flags are unchanged
        assert!(env.state.contexts[child_idx].allow_x509());
        assert!(!env.state.contexts[child_idx].uses_internal_input_info());
        assert!(!env.state.contexts[child_idx].uses_internal_input_dice());
        // Still using the same context.
        assert!(env.state.contexts[child_idx].allow_export_cdi());

        // check tci_cumulative correctly computed
        let mut hasher = env.crypto.hash_initialize().unwrap();
        hasher.update(&[0u8; DPE_PROFILE.hash_size()]).unwrap();
        hasher.update(&[1u8; DPE_PROFILE.hash_size()]).unwrap();
        let temp_digest = hasher.finish().unwrap();
        let mut hasher_2 = env.crypto.hash_initialize().unwrap();
        hasher_2.update(temp_digest.as_slice()).unwrap();
        hasher_2.update(&[2u8; DPE_PROFILE.hash_size()]).unwrap();
        let digest = hasher_2.finish().unwrap();
        assert_eq!(
            digest.as_slice(),
            env.state.contexts[child_idx].tci.tci_cumulative.0
        );
    }

    #[test]
    fn test_cdi_export_flags() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::AUTO_INIT
                | Support::CDI_EXPORT
                | Support::X509
                | Support::RECURSIVE
                | Support::SIMULATION
                | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        // When `DeriveContextFlags::EXPORT_CDI` is set, `DeriveContextFlags::CREATE_CERTIFICATE` MUST
        // also be set, or `DpeErrorCode::InvalidArgument` is raised.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CHANGE_LOCALITY,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[1],
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::RECURSIVE,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // `DeriveContextFlags::EXPORT_CDI` cannot be set with `DeriveContextFlags::RETAIN_PARENT_CONTEXT`
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
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
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::CREATE_CERTIFICATE | DeriveContextFlags::EXPORT_CDI,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // DPE must return an `DpeErrorCode::InvalidArgument` if `DeriveContextFlags::EXPORT_CDI` and `DeriveContextFlags::RECURSIVE` are set.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::CREATE_CERTIFICATE
                    | DeriveContextFlags::EXPORT_CDI
                    | DeriveContextFlags::RECURSIVE,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        *env.state = State::new(
            Support::AUTO_INIT | Support::CDI_EXPORT | Support::X509,
            DpeFlags::empty(),
        );
        dpe = DpeInstance::new(&mut env).unwrap();

        // Happy case!
        let res = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
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

        *env.state = State::new(
            Support::AUTO_INIT | Support::INTERNAL_INFO | Support::INTERNAL_DICE | Support::X509,
            DpeFlags::empty(),
        );
        dpe = DpeInstance::new(&mut env).unwrap();

        // `DpeInstance` needs `Support::EXPORT_CDI` to use `DeriveContextFlags::EXPORT_CDI`.
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::CREATE_CERTIFICATE | DeriveContextFlags::EXPORT_CDI,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // `DpeInstance` needs `Support::EXPORT_CDI` to use `DeriveContextFlags::EXPORT_CDI`.
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // `DpeInstance` needs `Support::EXPORT_CDI` to use `DeriveContextFlags::EXPORT_CDI`.
        assert_eq!(
            Err(DpeErrorCode::ArgumentNotSupported),
            DeriveContextCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::CREATE_CERTIFICATE,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // New ENV so the exported-cdi slot is clear.
        let mut state = State::new(
            Support::AUTO_INIT
                | Support::CDI_EXPORT
                | Support::X509
                | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        let Ok(Response::DeriveContext(DeriveContextResp { handle, .. })) = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]) else {
            panic!("exptected a valid DeriveContextResp");
        };

        let res = DeriveContextCmd {
            handle,
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::EXPORT_CDI
                | DeriveContextFlags::CREATE_CERTIFICATE
                | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]);

        // When `DeriveContextFlags::RETAIN_PARENT_CONTEXT` a new handle to the parent should be
        // returned.
        let res = match res {
            Ok(Response::DeriveContextExportedCdi(res)) => res,
            Err(e) => panic!("{:?}", e),
            _ => panic!("expected to get a valid DeriveContextExportedCdi response."),
        };
        assert_ne!(res.parent_handle, handle);
        assert_eq!(res.handle, ContextHandle::new_invalid());
        assert_ne!(res.certificate_size, 0);
        assert_ne!(res.new_certificate, [0; MAX_CERT_SIZE]);
        assert_ne!(res.exported_cdi, [0; MAX_EXPORTED_CDI_SIZE]);

        // New ENV so the exported-cdi slot is clear.
        let mut state = State::new(
            Support::AUTO_INIT
                | Support::CDI_EXPORT
                | Support::X509
                | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        // When `DeriveContextFlags::RETAIN_PARENT_CONTEXT` a new handle to the parent should be
        // returned. If the default handle was used, it should be the default handle.
        let res = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::EXPORT_CDI
                | DeriveContextFlags::CREATE_CERTIFICATE
                | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]);

        let res = match res {
            Ok(Response::DeriveContextExportedCdi(res)) => res,
            _ => panic!("expected to get a valid DeriveContextExportedCdi response."),
        };
        assert_eq!(res.parent_handle, ContextHandle::default());
        assert_eq!(res.handle, ContextHandle::new_invalid());
        assert_ne!(res.certificate_size, 0);
        assert_ne!(res.new_certificate, [0; MAX_CERT_SIZE]);
        assert_ne!(res.exported_cdi, [0; MAX_EXPORTED_CDI_SIZE]);

        // Children that did not have `DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT` should not
        // be able to use `DeriveContextFlags::EXPORT_CDI`.
        *env.state = State::new(
            Support::AUTO_INIT | Support::CDI_EXPORT | Support::X509,
            DpeFlags::empty(),
        );
        dpe = DpeInstance::new(&mut env).unwrap();

        let Ok(Response::DeriveContext(res)) = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0xA; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::empty(),
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]) else {
            panic!("Unexpected result!");
        };

        let child_idx = env.state.get_active_context_pos(&res.handle, 0).unwrap();
        assert!(!env.state.contexts[child_idx].allow_export_cdi());

        let res = DeriveContextCmd {
            handle: res.handle,
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]);
        assert_eq!(res, Err(DpeErrorCode::InvalidArgument));

        // Children that did not have `DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT` should not
        // be able to use `DeriveContextFlags::EXPORT_CDI` even if `DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT`
        // was included.
        *env.state = State::new(
            Support::AUTO_INIT | Support::CDI_EXPORT | Support::X509,
            DpeFlags::empty(),
        );
        dpe = DpeInstance::new(&mut env).unwrap();

        let Ok(Response::DeriveContext(res)) = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0xA; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::empty(),
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]) else {
            panic!("Unexpected result!");
        };
        let child_idx = env.state.get_active_context_pos(&res.handle, 0).unwrap();
        assert!(!env.state.contexts[child_idx].allow_export_cdi());

        let res = DeriveContextCmd {
            handle: res.handle,
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::EXPORT_CDI
                | DeriveContextFlags::CREATE_CERTIFICATE
                | DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]);
        assert_eq!(res, Err(DpeErrorCode::InvalidArgument));

        // Children whose parents set `DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT` should be able to
        // use `DeriveContextFlags::EXPORT_CDI`.

        // Create a new env to clear cached exported CDIs
        let mut state = State::new(
            Support::AUTO_INIT | Support::CDI_EXPORT | Support::X509,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        let res = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0xA; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]);
        let child_idx = env
            .state
            .get_active_context_pos(&ContextHandle::default(), 0)
            .unwrap();
        assert!(env.state.contexts[child_idx].allow_export_cdi());

        let res = match res {
            Ok(Response::DeriveContext(res)) => res,
            _ => panic!("expected to get a valid DeriveContext response."),
        };

        let res = DeriveContextCmd {
            handle: res.handle,
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::EXPORT_CDI
                | DeriveContextFlags::CREATE_CERTIFICATE,
            tci_type: 0,
            target_locality: TEST_LOCALITIES[0],
            svn: 0,
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
    }

    #[test]
    fn export_cdi_parent_without_children() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::AUTO_INIT | Support::CDI_EXPORT | Support::X509,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        let res = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]);

        let Ok(Response::DeriveContextExportedCdi(_)) = res else {
            panic!("expected to get a valid DeriveContextExportedCdi response.");
        };

        // Make sure we did not leak a context.
        assert_eq!(
            env.state
                .contexts
                .iter()
                .filter(|&c| c.state == ContextState::Inactive)
                .count(),
            env.state.contexts.len()
        );
        let validator = DpeValidator {
            dpe: &mut env.state,
        };
        assert!(validator.validate_dpe().is_ok());
    }

    #[test]
    fn export_cdi_parent_retained() {
        CfiCounter::reset_for_test();
        let mut state = State::new(
            Support::AUTO_INIT
                | Support::CDI_EXPORT
                | Support::X509
                | Support::RETAIN_PARENT_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        let res = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::EXPORT_CDI
                | DeriveContextFlags::CREATE_CERTIFICATE
                | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]);

        let Ok(Response::DeriveContextExportedCdi(_)) = res else {
            panic!("expected to get a valid DeriveContextExportedCdi response.");
        };

        let validator = DpeValidator {
            dpe: &mut env.state,
        };
        assert!(validator.validate_dpe().is_ok());

        // Parent is still valid.
        assert_eq!(
            env.state
                .contexts
                .iter()
                .filter(|&c| c.state == ContextState::Active)
                .count(),
            1
        );
    }

    #[test]
    fn export_cdi_child_with_siblings() {
        CfiCounter::reset_for_test();
        // This test will export a CDI that has multiple siblings without retaining the parent.
        // We verify:
        // * DPE is in a valid state after the test.
        // * Active siblings are not destroyed.
        // * The grand-parent remains active.

        let mut state = State::new(
            Support::AUTO_INIT
                | Support::CDI_EXPORT
                | Support::X509
                | Support::RETAIN_PARENT_CONTEXT
                | Support::ROTATE_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        // We want to use multiple contexts, so rotate out the default handle for a new handle.
        let Ok(Response::RotateCtx(NewHandleResp {
            handle: root_handle,
            ..
        })) = RotateCtxCmd {
            handle: ContextHandle::default(),
            flags: RotateCtxFlags::empty(),
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        else {
            panic!("Failed to rotate default handle")
        };

        let children_count = 3;
        let mut handle = ContextHandle::new_invalid();
        let mut parent_handle = root_handle;
        for i in 1..=children_count {
            // Children + Parent
            let expected_active_contexts = i + 1;
            // Create the next context from the current context.
            (handle, parent_handle) = derive_context_and_check_active_child_count(
                &mut dpe,
                &mut env,
                DeriveContextCmd {
                    handle: parent_handle,
                    data: [0; DPE_PROFILE.tci_size()],
                    flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
                        | DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT,
                    tci_type: 0,
                    target_locality: TEST_LOCALITIES[0],
                    svn: 0,
                },
                expected_active_contexts,
            );
        }

        let root_idx = env
            .state
            .get_active_context_pos(&parent_handle, TEST_LOCALITIES[0])
            .unwrap();
        let exported_idx = env
            .state
            .get_active_context_pos(&handle, TEST_LOCALITIES[0])
            .unwrap();

        // The `expected_active_contexts` = the children + the root parent - destroyed sibling.
        let expected_active_contexts = (children_count + 1) - 1;

        // Export a CDI and verify that the parent context is `destroyed`. Check that siblings remain active.
        let _ = derive_context_and_check_active_child_count(
            &mut dpe,
            &mut env,
            DeriveContextCmd {
                handle,
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
            },
            expected_active_contexts,
        );

        // The parent of the exported CDI is destroyed.
        assert_eq!(
            env.state.contexts[exported_idx].state,
            ContextState::Inactive
        );
        assert_eq!(
            env.state.contexts[exported_idx].handle,
            ContextHandle::new_invalid()
        );

        // The root node should not have been destroyed since it has other children.
        assert_eq!(env.state.contexts[root_idx].state, ContextState::Active);
        assert_eq!(env.state.contexts[root_idx].handle, parent_handle);

        let validator = DpeValidator {
            dpe: &mut env.state,
        };
        assert!(validator.validate_dpe().is_ok());
    }

    #[test]
    fn export_cdi_parent_with_children() {
        CfiCounter::reset_for_test();
        // This test will export a CDI that has multiple children without retaining the parent.
        // We verify:
        // * DPE is in a valid state after the test.
        // * Active siblings are not destroyed.
        // * The parent is retired, instead of destroyed, since it has active children.

        let mut state = State::new(
            Support::AUTO_INIT
                | Support::CDI_EXPORT
                | Support::X509
                | Support::RETAIN_PARENT_CONTEXT
                | Support::ROTATE_CONTEXT,
            DpeFlags::empty(),
        );
        let mut env = test_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env).unwrap();

        // We want to use multiple contexts, so rotate out the default handle for a new handle.
        let Ok(Response::RotateCtx(NewHandleResp {
            handle: root_handle,
            ..
        })) = RotateCtxCmd {
            handle: ContextHandle::default(),
            flags: RotateCtxFlags::empty(),
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        else {
            panic!("Failed to rotate default handle")
        };

        let children_count = 3;
        let mut parent_handle = root_handle;
        for i in 1..=children_count {
            // Children + Parent
            let expected_active_contexts = i + 1;
            // Create the next context from the current context.
            (_, parent_handle) = derive_context_and_check_active_child_count(
                &mut dpe,
                &mut env,
                DeriveContextCmd {
                    handle: parent_handle,
                    data: [0; DPE_PROFILE.tci_size()],
                    flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
                    tci_type: 0,
                    target_locality: TEST_LOCALITIES[0],
                    svn: 0,
                },
                expected_active_contexts,
            );
        }

        let parent_idx = env
            .state
            .get_active_context_pos(&parent_handle, TEST_LOCALITIES[0])
            .unwrap();

        let expected_active_contexts = children_count;

        // Now export the parent context and expect that the parent context is retired and all
        // children remain active.
        let _ = derive_context_and_check_active_child_count(
            &mut dpe,
            &mut env,
            DeriveContextCmd {
                handle: parent_handle,
                data: [0; DPE_PROFILE.tci_size()],
                flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
            },
            expected_active_contexts,
        );

        assert_eq!(env.state.contexts[parent_idx].state, ContextState::Retired);
        assert_eq!(
            env.state.contexts[parent_idx].handle,
            ContextHandle::new_invalid()
        );

        let validator = DpeValidator {
            dpe: &mut env.state,
        };
        assert!(validator.validate_dpe().is_ok());
    }

    #[test]
    fn test_create_ca() {
        for mark_dice_extensions_critical in [true, false] {
            CfiCounter::reset_for_test();
            let flags = {
                let mut flags = DpeFlags::empty();
                flags.set(
                    DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL,
                    mark_dice_extensions_critical,
                );
                flags
            };
            let mut state = State::new(Support::X509 | Support::CDI_EXPORT, flags);
            let mut env = test_env(&mut state);
            let mut dpe = DpeInstance::new(&mut env).unwrap();

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
                data: [0; DPE_PROFILE.tci_size()],
                tci_type: 0,
                target_locality: TEST_LOCALITIES[0],
                svn: 0,
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
            match parser.parse(
                &derive_resp.new_certificate[..derive_resp.certificate_size.try_into().unwrap()],
            ) {
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
                        DpeProfile::P256Sha256 => {
                            OpenSSLHasher::new(MessageDigest::sha256()).unwrap()
                        }
                        DpeProfile::P384Sha384 => {
                            OpenSSLHasher::new(MessageDigest::sha384()).unwrap()
                        }
                    };
                    hasher.update(pub_key).unwrap();
                    let expected_ski: &[u8] = &hasher.finish().unwrap();
                    match cert.get_extension_unique(&oid!(2.5.29 .14)) {
                        Ok(Some(subject_key_identifier_ext)) => {
                            if let ParsedExtension::SubjectKeyIdentifier(key_identifier) =
                                subject_key_identifier_ext.parsed_extension()
                            {
                                assert_eq!(
                                    key_identifier.0,
                                    &expected_ski[..MAX_KEY_IDENTIFIER_SIZE]
                                );
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

                    for extension in cert.iter_extensions() {
                        // Unknown extensions are DICE extensions, and they should match the
                        // criticality set by the DPE instance.
                        if extension.parsed_extension().unsupported() {
                            assert_eq!(extension.critical, mark_dice_extensions_critical);
                        }
                    }
                }
                Err(e) => panic!("x509 parsing failed: {:?}", e),
            };
        }
    }

    fn derive_context_and_check_active_child_count(
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<TestTypes>,
        cmd: DeriveContextCmd,
        expected_active_child_count: usize,
    ) -> (ContextHandle, ContextHandle) {
        match cmd.execute(dpe, env, TEST_LOCALITIES[0]) {
            Ok(Response::DeriveContext(DeriveContextResp {
                handle,
                parent_handle,
                ..
            }))
            | Ok(Response::DeriveContextExportedCdi(DeriveContextExportedCdiResp {
                handle,
                parent_handle,
                ..
            })) => {
                assert_eq!(
                    env.state
                        .count_contexts(|context: &Context| context.state == ContextState::Active),
                    Ok(expected_active_child_count)
                );
                (handle, parent_handle)
            }
            _ => panic!("expected to get a valid DeriveContext response"),
        }
    }
}
