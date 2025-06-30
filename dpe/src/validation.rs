// Licensed under the Apache-2.0 license.

use crate::{
    context::{Context, ContextState, ContextType},
    dpe_instance::flags_iter,
    response::DpeErrorCode,
    tci::TciNodeData,
    DpeInstance, MAX_HANDLES,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
/// It is possible that there are multiple issues with the DPE state. At most one will be found.
/// There is no priority on which error will be found first if there are multiple.
pub enum ValidationError {
    MultipleNormalConnectedComponents = 0x0,
    CyclesInTree = 0x1,
    InactiveContextInvalidParent = 0x2,
    InactiveContextWithChildren = 0x3,
    BadContextState = 0x4,
    BadContextType = 0x5,
    InactiveContextWithMeasurement = 0x6,
    MixedContextLocality = 0x7,
    MultipleDefaultContexts = 0x8,
    SimulationNotSupported = 0x9,
    ParentDoesNotExist = 0xA,
    InternalDiceNotSupported = 0xB,
    InternalInfoNotSupported = 0xC,
    ChildDoesNotExist = 0xD,
    InactiveContextWithFlagSet = 0xE,
    LocalityMismatch = 0xF,
    DanglingRetiredContext = 0x10,
    MixedContextTypeConnectedComponents = 0x11,
    ChildWithMultipleParents = 0x12,
    ParentChildLinksCorrupted = 0x13,
    AllowCaNotSupported = 0x14,
    AllowX509NotSupported = 0x15,
    InactiveParent = 0x16,
    InactiveChild = 0x17,
    DpeNotMarkedInitialized = 0x18,
}

impl ValidationError {
    pub fn discriminant(&self) -> u16 {
        *self as u16
    }
}

pub struct DpeValidator<'a> {
    pub dpe: &'a mut DpeInstance,
}

impl DpeValidator<'_> {
    /// Validates that the shape of the DPE instance is well-formed and that
    /// there is no illegal state present within the DPE.
    pub fn validate_dpe(&self) -> Result<(), DpeErrorCode> {
        self.validate_dpe_state()
            .map_err(DpeErrorCode::Validation)?;

        self.validate_context_forest()
            .map_err(DpeErrorCode::Validation)
    }

    /// Returns an error if there is any illegal state or inconsistencies
    /// present within the DPE instance.
    fn validate_dpe_state(&self) -> Result<(), ValidationError> {
        for i in 0..MAX_HANDLES {
            let context = &self.dpe.contexts[i];

            self.check_support(context)?;

            match context.state {
                ContextState::Inactive => self.validate_inactive_context(context)?,

                ContextState::Active => {
                    // has_initialized must be true if there is a normal, active context
                    if context.context_type == ContextType::Normal && !self.dpe.has_initialized() {
                        return Err(ValidationError::DpeNotMarkedInitialized);
                    }
                    self.check_children_and_parent(i)?;
                }
                ContextState::Retired => {
                    self.check_children_and_parent(i)?;
                    // retired contexts must have at least one child context
                    let child_context_count = flags_iter(context.children, MAX_HANDLES).count();
                    if child_context_count == 0 {
                        return Err(ValidationError::DanglingRetiredContext);
                    }
                }
            }

            if context.context_type != ContextType::Normal
                && context.context_type != ContextType::Simulation
            {
                return Err(ValidationError::BadContextType);
            }

            if context.locality != context.tci.locality {
                return Err(ValidationError::LocalityMismatch);
            }
        }

        self.check_context_handles_per_locality()?;

        Ok(())
    }

    /// Checks that the context fields do not violate supported flags
    fn check_support(&self, context: &Context) -> Result<(), ValidationError> {
        if !self.dpe.support.simulation() && context.context_type == ContextType::Simulation {
            return Err(ValidationError::SimulationNotSupported);
        }
        if !self.dpe.support.internal_dice() && context.uses_internal_input_dice() {
            return Err(ValidationError::InternalDiceNotSupported);
        }
        if !self.dpe.support.internal_info() && context.uses_internal_input_info() {
            return Err(ValidationError::InternalInfoNotSupported);
        }
        // initialized contexts will always have parent = Context::ROOT_INDEX and then the allow_x509
        // field will always be true regardless of support.
        if context.parent_idx != Context::ROOT_INDEX
            && !self.dpe.support.x509()
            && context.allow_x509()
        {
            return Err(ValidationError::AllowX509NotSupported);
        }
        Ok(())
    }

    /// Checks that the fields of an inactive context are all default
    fn validate_inactive_context(&self, context: &Context) -> Result<(), ValidationError> {
        if context.parent_idx != Context::ROOT_INDEX {
            Err(ValidationError::InactiveContextInvalidParent)
        } else if context.children != 0 {
            Err(ValidationError::InactiveContextWithChildren)
        } else if context.tci != TciNodeData::default() {
            Err(ValidationError::InactiveContextWithMeasurement)
        } else if context.uses_internal_input_dice()
            || context.allow_x509()
            || context.uses_internal_input_info()
        {
            Err(ValidationError::InactiveContextWithFlagSet)
        } else {
            Ok(())
        }
    }

    /// Checks that children and parent indices of a context are valid
    fn check_children_and_parent(&self, idx: usize) -> Result<(), ValidationError> {
        let context = &self.dpe.contexts[idx];
        // Check if parent does not exist
        if context.parent_idx as usize >= MAX_HANDLES && context.parent_idx != Context::ROOT_INDEX {
            return Err(ValidationError::ParentDoesNotExist);
        }
        if context.parent_idx != Context::ROOT_INDEX {
            if self.dpe.contexts[context.parent_idx as usize].state == ContextState::Inactive {
                return Err(ValidationError::InactiveParent);
            }
            // Check that parent's children contains idx
            if self.dpe.contexts[context.parent_idx as usize].children & (1 << idx) == 0 {
                return Err(ValidationError::ParentChildLinksCorrupted);
            }
        }
        // Check if any children do not exist
        for child in flags_iter(context.children, 32) {
            if child >= MAX_HANDLES {
                return Err(ValidationError::ChildDoesNotExist);
            }
            if self.dpe.contexts[child].state == ContextState::Inactive {
                return Err(ValidationError::InactiveChild);
            }
            // Check that each child's parent is idx
            if self.dpe.contexts[child].parent_idx as usize != idx {
                return Err(ValidationError::ParentChildLinksCorrupted);
            }
        }
        Ok(())
    }

    /// Checks if there are multiple active default contexts or a mix of default
    /// and non-default contexts within the same locality.
    fn check_context_handles_per_locality(&self) -> Result<(), ValidationError> {
        for locality in self.dpe.contexts.iter().map(|context| context.locality) {
            let mut default_count = 0;
            let mut non_default_count = 0;
            for context in self.dpe.contexts.iter() {
                if context.locality == locality && context.state == ContextState::Active {
                    if context.handle.is_default() {
                        default_count += 1;
                    } else {
                        non_default_count += 1;
                    }
                }
                if default_count > 1 {
                    return Err(ValidationError::MultipleDefaultContexts);
                }
                if default_count > 0 && non_default_count > 0 {
                    return Err(ValidationError::MixedContextLocality);
                }
            }
        }

        Ok(())
    }

    /// Determines if the context array represents a valid collection of disjoint
    /// directed connnected acyclic graphs (forest) using depth-first search.
    fn validate_context_forest(&self) -> Result<(), ValidationError> {
        let mut seen = [false; MAX_HANDLES];
        let mut in_degree = [0; MAX_HANDLES];

        // count in degree of each node
        for context in self.dpe.contexts.iter() {
            for child in flags_iter(context.children, MAX_HANDLES) {
                if child >= MAX_HANDLES {
                    return Err(ValidationError::ChildDoesNotExist);
                }
                in_degree[child] += 1;
            }
        }

        for node_in_degree in in_degree {
            // all nodes must have only one parent
            if node_in_degree > 1 {
                return Err(ValidationError::ChildWithMultipleParents);
            }
        }

        let mut normal_tree_count = 0;
        for (i, (context, node_in_degree)) in self.dpe.contexts.iter().zip(in_degree).enumerate() {
            // dfs from all root nodes
            if node_in_degree == 0 && context.state != ContextState::Inactive {
                let context_type = context.context_type;
                if context_type == ContextType::Normal {
                    normal_tree_count += 1;
                }
                self.detect_invalid_subtree(i, &mut seen, context_type)?;
            }
        }
        // there can be at most one tree of contexts with ContextType::Normal
        if normal_tree_count > 1 {
            return Err(ValidationError::MultipleNormalConnectedComponents);
        }

        // if any node is undiscovered the graph must have a simple cycle
        for (context, node_visited) in self.dpe.contexts.iter().zip(seen) {
            if context.state != ContextState::Inactive && !node_visited {
                return Err(ValidationError::CyclesInTree);
            }
        }

        Ok(())
    }

    fn detect_invalid_subtree(
        &self,
        curr_idx: usize,
        seen: &mut [bool; MAX_HANDLES],
        context_type: ContextType,
    ) -> Result<(), ValidationError> {
        // if the current node was already visited we have a cycle
        if curr_idx >= MAX_HANDLES
            || self.dpe.contexts[curr_idx].state == ContextState::Inactive
            || seen[curr_idx]
        {
            return Err(ValidationError::CyclesInTree);
        }
        // all nodes in the tree must have the same ContextType
        if self.dpe.contexts[curr_idx].context_type != context_type {
            return Err(ValidationError::MixedContextTypeConnectedComponents);
        }
        seen[curr_idx] = true;
        // dfs on all child nodes
        for child_idx in flags_iter(self.dpe.contexts[curr_idx].children, MAX_HANDLES) {
            self.detect_invalid_subtree(child_idx, seen, context_type)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::OpensslCrypto;
    use platform::default::DefaultPlatform;

    use crate::{
        context::{Context, ContextHandle, ContextState, ContextType},
        dpe_instance::{tests::TestTypes, DpeEnv, DpeInstanceFlags},
        support::{test::SUPPORT, Support},
        tci::TciMeasurement,
        validation::{DpeValidator, ValidationError},
        DpeInstance, U8Bool, DPE_PROFILE,
    };

    #[test]
    fn test_validate_context_forest() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let dpe_validator = DpeValidator {
            dpe: &mut DpeInstance::new(&mut env, SUPPORT, DpeInstanceFlags::empty()).unwrap(),
        };

        // validation fails on graph where child has multiple parents
        dpe_validator.dpe.contexts[0].state = ContextState::Active;
        dpe_validator.dpe.contexts[0].children = 0b100;
        dpe_validator.dpe.contexts[1].state = ContextState::Active;
        dpe_validator.dpe.contexts[1].children = 0b100;
        dpe_validator.dpe.contexts[2].state = ContextState::Active;
        assert_eq!(
            dpe_validator.validate_context_forest(),
            Err(ValidationError::ChildWithMultipleParents)
        );

        // validation passes on a tree in the shape of a linked-list
        dpe_validator.dpe.contexts[0].children = 0b10;
        assert_eq!(dpe_validator.validate_context_forest(), Ok(()));

        // validation fails on circle graph with a simple cycle
        dpe_validator.dpe.contexts[2].children = 0b1;
        assert_eq!(
            dpe_validator.validate_context_forest(),
            Err(ValidationError::CyclesInTree)
        );

        // validation passes on a complete binary tree of size 2
        dpe_validator.dpe.contexts[0].children |= 0b100;
        dpe_validator.dpe.contexts[1].children = 0;
        dpe_validator.dpe.contexts[2].children = 0;
        assert_eq!(dpe_validator.validate_context_forest(), Ok(()));

        // validation fails on multiple normal trees in forest
        dpe_validator.dpe.contexts[10].state = ContextState::Active;
        dpe_validator.dpe.contexts[10].children = (1 << 11) | (1 << 12);
        dpe_validator.dpe.contexts[11].state = ContextState::Active;
        dpe_validator.dpe.contexts[12].state = ContextState::Active;
        assert_eq!(
            dpe_validator.validate_context_forest(),
            Err(ValidationError::MultipleNormalConnectedComponents)
        );

        // validation passes on forest with normal tree and simulation tree
        dpe_validator.dpe.contexts[10].context_type = ContextType::Simulation;
        dpe_validator.dpe.contexts[11].context_type = ContextType::Simulation;
        dpe_validator.dpe.contexts[12].context_type = ContextType::Simulation;
        assert_eq!(dpe_validator.validate_context_forest(), Ok(()));

        // validation fails on tree with both simulation and normal contexts
        dpe_validator.dpe.contexts[11].context_type = ContextType::Normal;
        assert_eq!(
            dpe_validator.validate_context_forest(),
            Err(ValidationError::MixedContextTypeConnectedComponents)
        );
    }

    #[test]
    fn test_support_validation() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let dpe_validator = DpeValidator {
            dpe: &mut DpeInstance::new(&mut env, Support::empty(), DpeInstanceFlags::empty())
                .unwrap(),
        };

        // test simulation support
        dpe_validator.dpe.contexts[0].context_type = ContextType::Simulation;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::SimulationNotSupported)
        );

        // test internal dice support
        dpe_validator.dpe.contexts[0].context_type = ContextType::Normal;
        dpe_validator.dpe.contexts[0].uses_internal_input_dice = U8Bool::new(true);
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::InternalDiceNotSupported)
        );

        // test internal info support
        dpe_validator.dpe.contexts[0].uses_internal_input_dice = U8Bool::new(false);
        dpe_validator.dpe.contexts[0].uses_internal_input_info = U8Bool::new(true);
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::InternalInfoNotSupported)
        );

        // test x509
        dpe_validator.dpe.contexts[0].parent_idx = 1;
        dpe_validator.dpe.contexts[0].uses_internal_input_info = U8Bool::new(false);
        dpe_validator.dpe.contexts[0].allow_x509 = U8Bool::new(true);
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::AllowX509NotSupported)
        );
    }

    #[test]
    fn test_context_specific_validation() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let dpe_validator = DpeValidator {
            dpe: &mut DpeInstance::new(
                &mut env,
                Support::all().difference(Support::AUTO_INIT),
                DpeInstanceFlags::empty(),
            )
            .unwrap(),
        };

        // inactive context validation
        dpe_validator.dpe.contexts[0].parent_idx = 0;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::InactiveContextInvalidParent)
        );

        dpe_validator.dpe.contexts[0].parent_idx = Context::ROOT_INDEX;
        dpe_validator.dpe.contexts[0].children = u32::MAX;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::InactiveContextWithChildren)
        );

        dpe_validator.dpe.contexts[0].children = 0;
        dpe_validator.dpe.contexts[0].tci.tci_current =
            TciMeasurement([1; DPE_PROFILE.get_tci_size()]);
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::InactiveContextWithMeasurement)
        );

        dpe_validator.dpe.contexts[0].tci.tci_current = TciMeasurement::default();
        dpe_validator.dpe.contexts[0].allow_x509 = U8Bool::new(true);
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::InactiveContextWithFlagSet)
        );

        // active context validation
        dpe_validator.dpe.has_initialized = U8Bool::new(true);
        dpe_validator.dpe.contexts[0].state = ContextState::Active;
        dpe_validator.dpe.contexts[0].parent_idx = 250;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::ParentDoesNotExist)
        );

        dpe_validator.dpe.contexts[0].parent_idx = Context::ROOT_INDEX;
        dpe_validator.dpe.contexts[0].children = 1 << 30;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::ChildDoesNotExist)
        );

        dpe_validator.dpe.contexts[0].children = 1 << 10;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::InactiveChild)
        );

        dpe_validator.dpe.contexts[0].children = 0;
        dpe_validator.dpe.contexts[0].parent_idx = 10;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::InactiveParent)
        );

        dpe_validator.dpe.contexts[10].state = ContextState::Active;
        dpe_validator.dpe.contexts[0].children = 1 << 10;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::ParentChildLinksCorrupted)
        );

        dpe_validator.dpe.contexts[0].children = 0;
        dpe_validator.dpe.contexts[0].parent_idx = 10;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::ParentChildLinksCorrupted)
        );

        dpe_validator.dpe.contexts[0].parent_idx = Context::ROOT_INDEX;
        dpe_validator.dpe.has_initialized = U8Bool::new(false);
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::DpeNotMarkedInitialized)
        );

        // retired context validation
        dpe_validator.dpe.has_initialized = U8Bool::new(true);
        dpe_validator.dpe.contexts[0].parent_idx = Context::ROOT_INDEX;
        dpe_validator.dpe.contexts[0].state = ContextState::Retired;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::DanglingRetiredContext)
        );

        // locality mismatch
        dpe_validator.dpe.contexts[0].state = ContextState::Active;
        dpe_validator.dpe.contexts[0].context_type = ContextType::Normal;
        dpe_validator.dpe.contexts[0].locality = 0;
        dpe_validator.dpe.contexts[0].tci.locality = 1;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::LocalityMismatch)
        );
    }

    #[test]
    fn test_contexts_within_same_locality_validation() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: OpensslCrypto::new(),
            platform: DefaultPlatform,
        };
        let dpe_validator = DpeValidator {
            dpe: &mut DpeInstance::new(&mut env, Support::empty(), DpeInstanceFlags::empty())
                .unwrap(),
        };
        dpe_validator.dpe.has_initialized = U8Bool::new(true);

        // multiple default contexts in same locality
        dpe_validator.dpe.contexts[0].state = ContextState::Active;
        dpe_validator.dpe.contexts[1].state = ContextState::Active;
        dpe_validator.dpe.contexts[0].locality = 0;
        dpe_validator.dpe.contexts[1].locality = 0;
        dpe_validator.dpe.contexts[0].handle = ContextHandle::default();
        dpe_validator.dpe.contexts[1].handle = ContextHandle::default();
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::MultipleDefaultContexts)
        );

        // default and non-default contexts in same locality
        dpe_validator.dpe.contexts[1].handle = ContextHandle([1u8; ContextHandle::SIZE]);
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::MixedContextLocality)
        );
    }
}
