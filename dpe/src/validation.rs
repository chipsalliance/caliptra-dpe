// Licensed under the Apache-2.0 license.

use crate::{
    context::{Context, ContextState, ContextType},
    dpe_instance::flags_iter,
    response::DpeErrorCode,
    tci::TciNodeData,
    DpeInstance, MAX_HANDLES,
};

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{
    cfi_assert, cfi_assert_eq, cfi_assert_le, cfi_assert_lt, cfi_assert_ne,
};
use cfg_if::cfg_if;

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
    VersionMismatch = 0x19,
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
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn validate_dpe(&self) -> Result<(), DpeErrorCode> {
        let dpe_state_validation = self.validate_dpe_state().map_err(DpeErrorCode::Validation);
        if cfi_launder(dpe_state_validation.is_ok()) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(dpe_state_validation.is_ok());
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(dpe_state_validation.is_err());
        }
        dpe_state_validation?;

        let context_forest_validation = self
            .validate_context_forest()
            .map_err(DpeErrorCode::Validation);
        if cfi_launder(context_forest_validation.is_ok()) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(context_forest_validation.is_ok());
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(context_forest_validation.is_err());
        }
        context_forest_validation
    }

    /// Returns an error if there is any illegal state or inconsistencies
    /// present within the DPE instance.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn validate_dpe_state(&self) -> Result<(), ValidationError> {
        if cfi_launder(self.dpe.version == DpeInstance::VERSION) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(self.dpe.version == DpeInstance::VERSION);
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(self.dpe.version != DpeInstance::VERSION);
            return Err(ValidationError::VersionMismatch);
        }
        for i in 0..MAX_HANDLES {
            let context = &self.dpe.contexts[i];

            let support_check = self.check_support(context);
            if cfi_launder(support_check.is_ok()) {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert!(support_check.is_ok());
            } else {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert!(support_check.is_err());
            }
            support_check?;

            match context.state {
                ContextState::Inactive => {
                    #[cfg(not(feature = "no-cfi"))]
                    cfi_assert_eq(context.state, ContextState::Inactive);
                    let inactive_context_validation = self.validate_inactive_context(context);
                    if cfi_launder(inactive_context_validation.is_ok()) {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert!(inactive_context_validation.is_ok());
                    } else {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert!(inactive_context_validation.is_err());
                    }
                    inactive_context_validation?;
                }
                ContextState::Active => {
                    #[cfg(not(feature = "no-cfi"))]
                    cfi_assert_eq(context.state, ContextState::Active);
                    // has_initialized must be true if there is a normal, active context
                    if context.context_type == ContextType::Normal && !self.dpe.has_initialized() {
                        return Err(ValidationError::DpeNotMarkedInitialized);
                    }
                    let children_and_parent_check = self.check_children_and_parent(i);
                    if cfi_launder(children_and_parent_check.is_ok()) {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert!(children_and_parent_check.is_ok());
                    } else {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert!(children_and_parent_check.is_err());
                    }
                    children_and_parent_check?;
                }
                ContextState::Retired => {
                    #[cfg(not(feature = "no-cfi"))]
                    cfi_assert_eq(context.state, ContextState::Retired);
                    let children_and_parent_check = self.check_children_and_parent(i);
                    if cfi_launder(children_and_parent_check.is_ok()) {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert!(children_and_parent_check.is_ok());
                    } else {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert!(children_and_parent_check.is_err());
                    }
                    children_and_parent_check?;
                    // retired contexts must have at least one child context
                    let child_context_count = flags_iter(context.children, MAX_HANDLES).count();
                    if cfi_launder(child_context_count) == 0 {
                        return Err(ValidationError::DanglingRetiredContext);
                    } else {
                        #[cfg(not(feature = "no-cfi"))]
                        cfi_assert_ne(child_context_count, 0);
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

            cfg_if! {
                if #[cfg(not(feature = "no-cfi"))] {
                    cfi_assert!(context.context_type == ContextType::Normal || context.context_type == ContextType::Simulation);
                    cfi_assert_eq(context.locality, context.tci.locality);
                }
            }
        }

        let context_handles_per_locality_check = self.check_context_handles_per_locality();
        if cfi_launder(context_handles_per_locality_check.is_ok()) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(context_handles_per_locality_check.is_ok());
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(context_handles_per_locality_check.is_err());
        }
        context_handles_per_locality_check?;

        Ok(())
    }

    /// Checks that the context fields do not violate supported flags
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
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
        cfg_if! {
            if #[cfg(not(feature = "no-cfi"))] {
                cfi_assert!(self.dpe.support.simulation() || context.context_type != ContextType::Simulation);
                cfi_assert!(self.dpe.support.internal_dice() || !context.uses_internal_input_dice());
                cfi_assert!(self.dpe.support.internal_info() || !context.uses_internal_input_info());
            }
        }
        // initialized contexts will always have parent = Context::ROOT_INDEX and then the allow_x509
        // field will always be true regardless of support.
        if context.parent_idx != Context::ROOT_INDEX {
            if !self.dpe.support.x509() && context.allow_x509() {
                return Err(ValidationError::AllowX509NotSupported);
            }
            cfg_if! {
                if #[cfg(not(feature = "no-cfi"))] {
                    cfi_assert!(self.dpe.support.x509() || !context.allow_x509());
                }
            }
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert_eq(context.parent_idx, Context::ROOT_INDEX);
        }
        Ok(())
    }

    /// Checks that the fields of an inactive context are all default
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
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
            cfg_if! {
                if #[cfg(not(feature = "no-cfi"))] {
                    cfi_assert_eq(context.parent_idx, Context::ROOT_INDEX);
                    cfi_assert_eq(context.children, 0);
                    cfi_assert_eq(context.tci, TciNodeData::default());
                    cfi_assert!(!context.uses_internal_input_dice());
                    cfi_assert!(!context.allow_x509());
                    cfi_assert!(!context.uses_internal_input_info());
                }
            }
            Ok(())
        }
    }

    /// Checks that children and parent indices of a context are valid
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
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
            cfg_if! {
                if #[cfg(not(feature = "no-cfi"))] {
                    cfi_assert_lt(child, MAX_HANDLES);
                    cfi_assert_ne(self.dpe.contexts[child].state, ContextState::Inactive);
                    cfi_assert_eq(self.dpe.contexts[child].parent_idx as usize, idx);
                }
            }
        }
        Ok(())
    }

    /// Checks if there are multiple active default contexts or a mix of default
    /// and non-default contexts within the same locality.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
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
            cfg_if! {
                if #[cfg(not(feature = "no-cfi"))] {
                    cfi_assert_le(default_count, 1);
                    cfi_assert!(!(default_count > 0 && non_default_count > 0));
                }
            }
        }

        Ok(())
    }

    /// Determines if the context array represents a valid collection of disjoint
    /// directed connnected acyclic graphs (forest) using depth-first search.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
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
            } else {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert_le(node_in_degree, 1);
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
                let invalid_subtree_check = self.detect_invalid_subtree(i, &mut seen, context_type);
                if cfi_launder(invalid_subtree_check.is_ok()) {
                    #[cfg(not(feature = "no-cfi"))]
                    cfi_assert!(invalid_subtree_check.is_ok());
                } else {
                    #[cfg(not(feature = "no-cfi"))]
                    cfi_assert!(invalid_subtree_check.is_err());
                }
                invalid_subtree_check?;
            }
        }
        // there can be at most one tree of contexts with ContextType::Normal
        if normal_tree_count > 1 {
            return Err(ValidationError::MultipleNormalConnectedComponents);
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert_le(normal_tree_count, 1);
        }

        // if any node is undiscovered the graph must have a simple cycle
        for (context, node_visited) in self.dpe.contexts.iter().zip(seen) {
            if context.state != ContextState::Inactive && !node_visited {
                return Err(ValidationError::CyclesInTree);
            } else {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert!(context.state == ContextState::Inactive || node_visited);
            }
        }

        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
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
        cfg_if! {
            if #[cfg(not(feature = "no-cfi"))] {
                cfi_assert_le(curr_idx, MAX_HANDLES);
                cfi_assert_ne(self.dpe.contexts[curr_idx].state, ContextState::Inactive);
                cfi_assert!(!seen[curr_idx]);
                cfi_assert_eq(self.dpe.contexts[curr_idx].context_type, context_type);
            }
        }
        seen[curr_idx] = true;
        // dfs on all child nodes
        for child_idx in flags_iter(self.dpe.contexts[curr_idx].children, MAX_HANDLES) {
            let invalid_subtree_check = self.detect_invalid_subtree(child_idx, seen, context_type);
            if cfi_launder(invalid_subtree_check.is_ok()) {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert!(invalid_subtree_check.is_ok());
            } else {
                #[cfg(not(feature = "no-cfi"))]
                cfi_assert!(invalid_subtree_check.is_err());
            }
            invalid_subtree_check?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use caliptra_cfi_lib_git::CfiCounter;
    use crypto::RustCryptoImpl;

    use crate::{
        commands::tests::DEFAULT_PLATFORM,
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
            crypto: RustCryptoImpl::new(),
            platform: DEFAULT_PLATFORM,
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
            crypto: RustCryptoImpl::new(),
            platform: DEFAULT_PLATFORM,
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
            crypto: RustCryptoImpl::new(),
            platform: DEFAULT_PLATFORM,
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
            crypto: RustCryptoImpl::new(),
            platform: DEFAULT_PLATFORM,
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

    #[test]
    fn test_version_mismatch() {
        CfiCounter::reset_for_test();
        let mut env = DpeEnv::<TestTypes> {
            crypto: RustCryptoImpl::new(),
            platform: DEFAULT_PLATFORM,
        };
        let dpe_validator = DpeValidator {
            dpe: &mut DpeInstance::new(&mut env, Support::empty(), DpeInstanceFlags::empty())
                .unwrap(),
        };
        assert_eq!(Ok(()), dpe_validator.validate_dpe_state());

        // Changing the version number should cause an error
        dpe_validator.dpe.version = 0;
        assert_eq!(
            dpe_validator.validate_dpe_state(),
            Err(ValidationError::VersionMismatch)
        );
    }
}
