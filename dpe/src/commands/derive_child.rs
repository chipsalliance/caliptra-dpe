// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    context::{ActiveContextArgs, Context, ContextHandle, ContextState, ContextType},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    response::{DeriveChildResp, DpeErrorCode, Response, ResponseHdr},
    tci::TciMeasurement,
    DPE_PROFILE,
};
use bitflags::bitflags;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes, zerocopy::AsBytes)]
pub struct DeriveChildFlags(u32);

bitflags! {
    impl DeriveChildFlags: u32 {
        const INTERNAL_INPUT_INFO = 1u32 << 31;
        const INTERNAL_INPUT_DICE = 1u32 << 30;
        const RETAIN_PARENT = 1u32 << 29;
        const MAKE_DEFAULT = 1u32 << 28;
        const CHANGE_LOCALITY = 1u32 << 27;
        const INPUT_ALLOW_CA = 1u32 << 26;
        const INPUT_ALLOW_X509 = 1u32 << 25;
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, zerocopy::FromBytes, zerocopy::AsBytes)]
pub struct DeriveChildCmd {
    pub handle: ContextHandle,
    pub data: [u8; DPE_PROFILE.get_hash_size()],
    pub flags: DeriveChildFlags,
    pub tci_type: u32,
    pub target_locality: u32,
}

impl DeriveChildCmd {
    const fn uses_internal_info_input(&self) -> bool {
        self.flags.contains(DeriveChildFlags::INTERNAL_INPUT_INFO)
    }

    const fn uses_internal_dice_input(&self) -> bool {
        self.flags.contains(DeriveChildFlags::INTERNAL_INPUT_DICE)
    }

    pub const fn retains_parent(&self) -> bool {
        self.flags.contains(DeriveChildFlags::RETAIN_PARENT)
    }

    const fn makes_default(&self) -> bool {
        self.flags.contains(DeriveChildFlags::MAKE_DEFAULT)
    }

    pub const fn changes_locality(&self) -> bool {
        self.flags.contains(DeriveChildFlags::CHANGE_LOCALITY)
    }

    const fn allows_ca(&self) -> bool {
        self.flags.contains(DeriveChildFlags::INPUT_ALLOW_CA)
    }

    const fn allows_x509(&self) -> bool {
        self.flags.contains(DeriveChildFlags::INPUT_ALLOW_X509)
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
    /// * `num_contexts_in_locality` - Number of contexts already in the locality.
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
        let num_contexts_in_locality = dpe.count_active_contexts_in_locality(target_locality)?;

        Ok(if self.makes_default() {
            self.safe_to_make_default(parent_idx, default_context_idx, num_contexts_in_locality)
        } else {
            self.safe_to_make_non_default(parent_idx, default_context_idx)
        })
    }
}

impl CommandExecution for DeriveChildCmd {
    fn execute(
        &self,
        dpe: &mut DpeInstance,
        env: &mut DpeEnv<impl DpeTypes>,
        locality: u32,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure the operation is supported.
        if (!dpe.support.internal_info() && self.uses_internal_info_input())
            || (!dpe.support.internal_dice() && self.uses_internal_dice_input())
        {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        if (!dpe.support.is_ca() && self.allows_ca()) || (!dpe.support.x509() && self.allows_x509())
        {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        let parent_idx = dpe.get_active_context_pos(&self.handle, locality)?;
        if (!dpe.contexts[parent_idx].allow_ca() && self.allows_ca())
            || (!dpe.contexts[parent_idx].allow_x509() && self.allows_x509())
        {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let child_idx = dpe
            .get_next_inactive_context_pos()
            .ok_or(DpeErrorCode::MaxTcis)?;

        let target_locality = if !self.changes_locality() {
            locality
        } else {
            self.target_locality
        };

        if !self.safe_to_make_child(dpe, parent_idx, target_locality)? {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let child_handle = if self.makes_default() {
            ContextHandle::default()
        } else {
            dpe.generate_new_handle(env)?
        };

        // Create a temporary context to mutate so that we avoid mutating internal state upon an error.
        let mut tmp_child_context = Context::new();
        tmp_child_context.activate(&ActiveContextArgs {
            context_type: ContextType::Normal,
            locality: target_locality,
            handle: &child_handle,
            tci_type: self.tci_type,
            parent_idx: parent_idx as u8,
            allow_ca: self.allows_ca(),
            allow_x509: self.allows_x509(),
        });

        dpe.add_tci_measurement(
            env,
            &mut tmp_child_context,
            &TciMeasurement(self.data),
            target_locality,
        )?;

        tmp_child_context.uses_internal_input_info = self.uses_internal_info_input().into();
        tmp_child_context.uses_internal_input_dice = self.uses_internal_dice_input().into();

        // Copy the parent context to mutate so that we avoid mutating internal state upon an error.
        let mut tmp_parent_context = dpe.contexts[parent_idx];
        if !self.retains_parent() {
            tmp_parent_context.state = ContextState::Retired;
            tmp_parent_context.handle = ContextHandle([0xff; ContextHandle::SIZE]);
        } else if !tmp_parent_context.handle.is_default() {
            tmp_parent_context.handle = dpe.generate_new_handle(env)?;
        }

        // Add child to the parent's list of children.
        let children_with_child_idx = tmp_parent_context.add_child(child_idx)?;
        tmp_parent_context.children = children_with_child_idx;

        // At this point we cannot error out anymore, so it is safe to set the updated child and parent contexts.
        dpe.contexts[child_idx] = tmp_child_context;
        dpe.contexts[parent_idx] = tmp_parent_context;

        Ok(Response::DeriveChild(DeriveChildResp {
            handle: child_handle,
            parent_handle: dpe.contexts[parent_idx].handle,
            resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
        }))
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
        dpe_instance::tests::{TestTypes, RANDOM_HANDLE, SIMULATION_HANDLE, TEST_LOCALITIES},
        support::Support,
        MAX_HANDLES,
    };
    use crypto::OpensslCrypto;
    use openssl::x509::X509;
    use openssl::{bn::BigNum, ecdsa::EcdsaSig};
    use platform::default::DefaultPlatform;
    use zerocopy::AsBytes;

    const TEST_DERIVE_CHILD_CMD: DeriveChildCmd = DeriveChildCmd {
        handle: SIMULATION_HANDLE,
        data: TEST_DIGEST,
        flags: DeriveChildFlags(0x1234_5678),
        tci_type: 0x9876_5432,
        target_locality: 0x10CA_1171,
    };

    #[test]
    fn test_deserialize_derive_child() {
        let mut command = CommandHdr::new_for_test(Command::DERIVE_CHILD)
            .as_bytes()
            .to_vec();
        command.extend(TEST_DERIVE_CHILD_CMD.as_bytes());
        assert_eq!(
            Ok(Command::DeriveChild(TEST_DERIVE_CHILD_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_initial_conditions() {
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
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveChildFlags::empty(),
                tci_type: 0,
                target_locality: 0
            }
            .execute(&mut dpe, &mut env, 1)
        );
    }

    #[test]
    fn test_max_tcis() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        // Fill all contexts with children (minus the auto-init context).
        for _ in 0..MAX_HANDLES - 1 {
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveChildFlags::MAKE_DEFAULT,
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
            .unwrap();
        }

        // Try to create one too many.
        assert_eq!(
            Err(DpeErrorCode::MaxTcis),
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveChildFlags::empty(),
                tci_type: 0,
                target_locality: 0
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_set_child_parent_relationship() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        let parent_idx = dpe
            .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
            .unwrap();
        DeriveChildCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveChildFlags::MAKE_DEFAULT | DeriveChildFlags::CHANGE_LOCALITY,
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
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        DeriveChildCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveChildFlags::MAKE_DEFAULT | DeriveChildFlags::CHANGE_LOCALITY,
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
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        // Make sure child handle is default when creating default child.
        assert_eq!(
            Ok(Response::DeriveChild(DeriveChildResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle([0xff; ContextHandle::SIZE]),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveChildFlags::MAKE_DEFAULT,
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Make sure child has a random handle when not creating default.
        assert_eq!(
            Ok(Response::DeriveChild(DeriveChildResp {
                handle: RANDOM_HANDLE,
                parent_handle: ContextHandle([0xff; ContextHandle::SIZE]),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveChildFlags::empty(),
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );
    }

    #[test]
    fn test_full_attestation_flow() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(
            &mut env,
            Support::INTERNAL_INFO | Support::X509 | Support::AUTO_INIT | Support::ROTATE_CONTEXT,
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

        let parent_handle = match (DeriveChildCmd {
            handle,
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveChildFlags::RETAIN_PARENT,
            tci_type: 0,
            target_locality: 0,
        })
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        {
            Ok(Response::DeriveChild(resp)) => resp.parent_handle,
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
                    BigNum::from_slice(&resp.sig_r_or_hmac).unwrap(),
                    BigNum::from_slice(&resp.sig_s).unwrap(),
                )
                .unwrap(),
            ),
            Ok(_) => panic!("Invalid response type"),
            Err(e) => Err(e).unwrap(),
        };

        let parent_handle = match (DeriveChildCmd {
            handle: new_context_handle,
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveChildFlags::RETAIN_PARENT | DeriveChildFlags::INTERNAL_INPUT_INFO,
            tci_type: 0,
            target_locality: 0,
        })
        .execute(&mut dpe, &mut env, 0)
        {
            Ok(Response::DeriveChild(resp)) => resp.parent_handle,
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
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        // Make sure the parent handle is non-sense when not retaining.
        assert_eq!(
            Ok(Response::DeriveChild(DeriveChildResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle([0xff; ContextHandle::SIZE]),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveChildFlags::MAKE_DEFAULT,
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        );

        // Make sure the default parent handle stays the default handle when retained.
        assert_eq!(
            Ok(Response::DeriveChild(DeriveChildResp {
                handle: ContextHandle::default(),
                parent_handle: ContextHandle::default(),
                resp_hdr: ResponseHdr::new(DpeErrorCode::NoError),
            })),
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveChildFlags::RETAIN_PARENT
                    | DeriveChildFlags::MAKE_DEFAULT
                    | DeriveChildFlags::CHANGE_LOCALITY,
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
        let Response::DeriveChild(DeriveChildResp {
            handle,
            parent_handle,
            resp_hdr,
        }) = DeriveChildCmd {
            handle: dpe.contexts[old_default_idx].handle,
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveChildFlags::RETAIN_PARENT,
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
        let mut make_default_in_0 = DeriveChildCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement::default().0,
            flags: DeriveChildFlags::MAKE_DEFAULT,
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

        make_default_in_0.flags |= DeriveChildFlags::RETAIN_PARENT;

        // Retain parent and make default in another locality that doesn't have a default.
        assert!(make_default_in_0.safe_to_make_default(parent_idx, None, 0));
        // Retain default parent and make default in another locality that has a default.
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, Some(1), 1));
        // Retain default parent.
        assert!(!make_default_in_0.safe_to_make_default(parent_idx, Some(parent_idx), 1));
    }

    #[test]
    fn test_safe_to_make_non_default() {
        let non_default = DeriveChildCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement::default().0,
            flags: DeriveChildFlags(0),
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
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        assert_eq!(
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: TciMeasurement::default().0,
                flags: DeriveChildFlags::RETAIN_PARENT,
                tci_type: 0,
                target_locality: 0,
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
            Err(DpeErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn test_make_default_in_other_locality_that_has_non_default() {
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let mut dpe = DpeInstance::new(&mut env, Support::AUTO_INIT).unwrap();

        DeriveChildCmd {
            handle: ContextHandle::default(),
            data: [0; DPE_PROFILE.get_tci_size()],
            flags: DeriveChildFlags::RETAIN_PARENT
                | DeriveChildFlags::MAKE_DEFAULT
                | DeriveChildFlags::CHANGE_LOCALITY,
            tci_type: 7,
            target_locality: TEST_LOCALITIES[1],
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

        assert_eq!(
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_tci_size()],
                flags: DeriveChildFlags::RETAIN_PARENT | DeriveChildFlags::CHANGE_LOCALITY,
                tci_type: 7,
                target_locality: TEST_LOCALITIES[1],
            }
            .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
            Err(DpeErrorCode::InvalidArgument)
        );
    }
}
