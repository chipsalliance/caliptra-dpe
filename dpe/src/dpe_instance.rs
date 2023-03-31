/*++
Licensed under the Apache-2.0 license.

Abstract:
    Defines an instance of DPE and all of its contexts.
--*/
use crate::{
    _set_flag,
    commands::{
        CertifyKeyCmd, Command, DeriveChildCmd, DestroyCtxCmd, ExtendTciCmd, InitCtxCmd,
        RotateCtxCmd, TagTciCmd,
    },
    response::{CertifyKeyResp, DpeErrorCode, GetProfileResp, NewHandleResp, Response},
    x509::{EcdsaPub, EcdsaSignature, MeasurementData, Name, X509CertWriter},
    DPE_PROFILE, HANDLE_SIZE, MAX_CERT_SIZE, MAX_HANDLES,
};
use core::convert::TryFrom;
use core::fmt::{Error, Write};
use core::marker::PhantomData;
use core::mem::size_of;
use crypto::{Crypto, Hasher};

pub struct DpeInstance<'a, C: Crypto> {
    contexts: [Context; MAX_HANDLES],
    support: Support,
    localities: &'a [u32],

    /// Can only successfully execute the initialize context command for non-simulation (i.e.
    /// `InitializeContext(simulation=false)`) once per reset cycle.
    has_initialized: bool,

    // All functions/data in C are static and global. For this reason
    // DpeInstance doesn't actually need to hold an instance. The PhantomData
    // is just to make the Crypto trait work.
    phantom: PhantomData<C>,
}

impl<C: Crypto> DpeInstance<'_, C> {
    const DEFAULT_CONTEXT_HANDLE: [u8; HANDLE_SIZE] = [0; HANDLE_SIZE];
    const MAX_NEW_HANDLE_ATTEMPTS: usize = 8;
    pub const AUTO_INIT_LOCALITY: u32 = 0;

    /// Create a new DPE instance.
    ///
    /// # Arguments
    ///
    /// * `support` - optional functionality the instance supports
    /// * `localities` - all possible valid localities for the system
    pub fn new(support: Support, localities: &[u32]) -> Result<DpeInstance<C>, DpeErrorCode> {
        if localities.is_empty() {
            return Err(DpeErrorCode::InvalidLocality);
        }
        const CONTEXT_INITIALIZER: Context = Context::new();
        let mut dpe = DpeInstance {
            contexts: [CONTEXT_INITIALIZER; MAX_HANDLES],
            support,
            localities,
            has_initialized: false,
            phantom: PhantomData,
        };

        if dpe.support.auto_init {
            // Make sure the auto-initialized locality is listed.
            if !localities.iter().any(|&l| l == Self::AUTO_INIT_LOCALITY) {
                return Err(DpeErrorCode::InvalidLocality);
            }
            dpe.initialize_context(Self::AUTO_INIT_LOCALITY, &InitCtxCmd::new_use_default())?;
        }
        Ok(dpe)
    }

    pub fn get_profile(&self) -> Result<GetProfileResp, DpeErrorCode> {
        Ok(GetProfileResp::new(self.support.get_flags()))
    }

    pub fn initialize_context(
        &mut self,
        locality: u32,
        cmd: &InitCtxCmd,
    ) -> Result<NewHandleResp, DpeErrorCode> {
        // This function can only be called once for non-simulation contexts.
        if (cmd.flag_is_default() && self.has_initialized)
            || (cmd.flag_is_simulation() && !self.support.simulation)
        {
            return Err(DpeErrorCode::ArgumentNotSupported);
        }

        // A flag must be set, but it can't be both flags. The base DPE CDI is locked for
        // non-simulation contexts once it is used once to prevent later software from accessing the
        // CDI.
        if !(cmd.flag_is_default() ^ cmd.flag_is_simulation()) {
            return Err(DpeErrorCode::InvalidArgument);
        }

        let idx = self
            .get_next_inactive_context_pos()
            .ok_or(DpeErrorCode::MaxTcis)?;
        let (context_type, handle) = if cmd.flag_is_default() {
            self.has_initialized = true;
            (ContextType::Normal, Self::DEFAULT_CONTEXT_HANDLE)
        } else {
            // Simulation.
            (ContextType::Simulation, self.generate_new_handle()?)
        };

        self.contexts[idx].activate(context_type, locality, &handle);
        Ok(NewHandleResp { handle })
    }

    pub fn derive_child(
        &mut self,
        _locality: u32,
        _cmd: &DeriveChildCmd,
    ) -> Result<Response, DpeErrorCode> {
        Err(DpeErrorCode::InvalidCommand)
    }

    /// Rotate the handle for given context to another random value. This also allows changing the
    /// locality of the context.
    pub fn rotate_context(
        &mut self,
        locality: u32,
        cmd: &RotateCtxCmd,
    ) -> Result<Response, DpeErrorCode> {
        if !self.support.rotate_context {
            return Err(DpeErrorCode::InvalidCommand);
        }
        let idx = self
            .get_active_context_pos(&cmd.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;

        // Make sure the command is coming from the right locality.
        if self.contexts[idx].locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }

        let new_handle = self.generate_new_handle()?;
        self.contexts[idx].handle = new_handle;
        Ok(Response::RotateCtx(NewHandleResp { handle: new_handle }))
    }

    /// Destroy a context and optionally all of its descendants.
    pub fn destroy_context(
        &mut self,
        locality: u32,
        cmd: &DestroyCtxCmd,
    ) -> Result<Response, DpeErrorCode> {
        let idx = self
            .get_active_context_pos(&cmd.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;
        let context = &self.contexts[idx];
        // Make sure the command is coming from the right locality.
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }

        let to_destroy = if cmd.flag_is_destroy_descendants() {
            (1 << idx) | self.get_descendants(context)?
        } else {
            1 << idx
        };

        for idx in flags_iter(to_destroy, MAX_HANDLES) {
            self.contexts[idx].destroy();
        }
        Ok(Response::DestroyCtx)
    }

    pub fn extend_tci(
        &mut self,
        locality: u32,
        cmd: &ExtendTciCmd,
    ) -> Result<Response, DpeErrorCode> {
        // Make sure this command is supported.
        if !self.support.extend_tci {
            return Err(DpeErrorCode::InvalidCommand);
        }
        let idx = self
            .get_active_context_pos(&cmd.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;
        let context = &mut self.contexts[idx];

        // Make sure the command is coming from the right locality.
        if context.locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }

        // Derive the new TCI.
        let mut hasher =
            C::hash_initialize(DPE_PROFILE.alg_len()).map_err(|_| DpeErrorCode::InternalError)?;
        hasher
            .update(&context.tci.tci_cumulative.0)
            .map_err(|_| DpeErrorCode::InternalError)?;
        hasher
            .update(&cmd.data)
            .map_err(|_| DpeErrorCode::InternalError)?;
        hasher
            .finish(&mut context.tci.tci_cumulative.0)
            .map_err(|_| DpeErrorCode::InternalError)?;

        context.tci.tci_current = TciMeasurement(cmd.data);
        // Rotate the handle if it isn't the default context.
        self.roll_onetime_use_handle(idx)?;
        Ok(Response::ExtendTci(NewHandleResp {
            handle: self.contexts[idx].handle,
        }))
    }

    pub fn tag_tci(&mut self, locality: u32, cmd: &TagTciCmd) -> Result<Response, DpeErrorCode> {
        // Make sure this command is supported.
        if !self.support.tagging {
            return Err(DpeErrorCode::InvalidCommand);
        }
        // Make sure the tag isn't used by any other contexts.
        if self.contexts.iter().any(|c| c.has_tag && c.tag == cmd.tag) {
            return Err(DpeErrorCode::BadTag);
        }

        let idx = self
            .get_active_context_pos(&cmd.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;

        // Make sure the command is coming from the right locality.
        if self.contexts[idx].locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }
        if self.contexts[idx].has_tag {
            return Err(DpeErrorCode::BadTag);
        }

        // Because handles are one-time use, let's rotate the handle, if it isn't the default.
        self.roll_onetime_use_handle(idx)?;
        let context = &mut self.contexts[idx];
        context.has_tag = true;
        context.tag = cmd.tag;

        Ok(Response::TagTci(NewHandleResp {
            handle: context.handle,
        }))
    }

    pub fn certify_key(
        &mut self,
        locality: u32,
        cmd: &CertifyKeyCmd,
    ) -> Result<CertifyKeyResp, DpeErrorCode> {
        let idx = self
            .get_active_context_pos(&cmd.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;

        // Make sure the command is coming from the right locality.
        if self.contexts[idx].locality != locality {
            return Err(DpeErrorCode::InvalidHandle);
        }

        // Get TCI Nodes
        const INITIALIZER: TciNodeData = TciNodeData::new();
        let mut nodes = [INITIALIZER; MAX_HANDLES];
        let tcb_count = self.get_tcb_nodes(&self.contexts[idx], &mut nodes)?;

        // Hash TCI Nodes
        let mut tci_bytes = [0u8; MAX_HANDLES * size_of::<TciNodeData>()];
        let mut tci_offset = 0;
        for n in &nodes[..tcb_count] {
            tci_offset += n.serialize(&mut tci_bytes[tci_offset..])?;
        }

        let mut digest = [0; DPE_PROFILE.get_hash_size()];
        C::hash(DPE_PROFILE.alg_len(), &tci_bytes[..tci_offset], &mut digest)
            .map_err(|_| DpeErrorCode::InternalError)?;

        // Derive CDI and public key
        let cdi = C::derive_cdi(DPE_PROFILE.alg_len(), &digest, b"DPE")
            .map_err(|_| DpeErrorCode::InternalError)?;
        let mut pub_key = EcdsaPub::default();
        C::derive_ecdsa_pub(
            DPE_PROFILE.alg_len(),
            &cdi,
            &cmd.label,
            b"ECC",
            &mut pub_key.x,
            &mut pub_key.y,
        )
        .map_err(|_| DpeErrorCode::InternalError)?;

        // Hash the public key for the serialNumber name field
        let mut pub_bytes = [0u8; size_of::<EcdsaPub>()];
        let pub_offset = pub_key.serialize(&mut pub_bytes)?;
        let mut pub_digest = [0u8; DPE_PROFILE.get_hash_size()];
        C::hash(
            DPE_PROFILE.alg_len(),
            &pub_bytes[..pub_offset],
            &mut pub_digest,
        )
        .map_err(|_| DpeErrorCode::InternalError)?;

        // TODO: Let the platform specify issuer name
        let issuer_name = Name {
            cn: b"DPE Issuer",
            serial: b"000000",
        };

        let mut subject_sn_str = [0u8; DPE_PROFILE.get_hash_size() * 2];
        let mut w = BufWriter {
            buf: &mut subject_sn_str,
            offset: 0,
        };
        w.write_hex_str(&pub_digest)?;

        let subject_name = Name {
            cn: b"DPE Leaf",
            serial: &subject_sn_str,
        };

        let measurements = MeasurementData {
            _label: &cmd.label,
            tci_nodes: &nodes[..tcb_count],
        };

        // Get certificate
        let mut tbs_buffer = [0u8; MAX_CERT_SIZE];
        let mut tbs_writer = X509CertWriter::new(&mut tbs_buffer);
        let mut bytes_written = tbs_writer.encode_ecdsa_tbs(
            /*serial=*/ &pub_digest,
            &issuer_name,
            &subject_name,
            &pub_key,
            &measurements,
        )?;

        let mut tbs_digest = [0u8; DPE_PROFILE.get_hash_size()];
        C::hash(
            DPE_PROFILE.alg_len(),
            &tbs_buffer[..bytes_written],
            &mut tbs_digest,
        )
        .map_err(|_| DpeErrorCode::InternalError)?;
        let mut sig = EcdsaSignature::default();
        C::ecdsa_sign_with_alias(DPE_PROFILE.alg_len(), &tbs_digest, &mut sig.r, &mut sig.s)
            .map_err(|_| DpeErrorCode::InternalError)?;

        let mut cert = [0u8; MAX_CERT_SIZE];
        let mut cert_writer = X509CertWriter::new(&mut cert);
        bytes_written = cert_writer.encode_ecdsa_certificate(&tbs_buffer[..bytes_written], &sig)?;
        let cert_size = u32::try_from(bytes_written).map_err(|_| DpeErrorCode::InternalError)?;

        // Rotate handle if it isn't the default
        self.roll_onetime_use_handle(idx)?;

        Ok(CertifyKeyResp {
            new_context_handle: self.contexts[idx].handle,
            derived_pubkey_x: pub_key.x,
            derived_pubkey_y: pub_key.y,
            cert_size,
            cert,
        })
    }

    /// Deserializes the command and executes it.
    ///
    /// # Arguments
    ///
    /// * `locality` - which hardware locality is making the request
    /// * `cmd` - serialized command
    pub fn execute_serialized_command(
        &mut self,
        locality: u32,
        cmd: &[u8],
    ) -> Result<Response, DpeErrorCode> {
        // Make sure the command is coming from a valid locality.
        if !self.localities.iter().any(|&l| l == locality) {
            return Err(DpeErrorCode::InvalidLocality);
        }
        let command = Command::deserialize(cmd)?;
        match command {
            Command::GetProfile => Ok(Response::GetProfile(self.get_profile()?)),
            Command::InitCtx(context) => Ok(Response::InitCtx(
                self.initialize_context(locality, &context)?,
            )),
            Command::DeriveChild(cmd) => self.derive_child(locality, &cmd),
            Command::CertifyKey(context) => {
                Ok(Response::CertifyKey(self.certify_key(locality, &context)?))
            }
            Command::RotateCtx(cmd) => self.rotate_context(locality, &cmd),
            Command::DestroyCtx(context) => self.destroy_context(locality, &context),
            Command::ExtendTci(cmd) => self.extend_tci(locality, &cmd),
            Command::TagTci(cmd) => self.tag_tci(locality, &cmd),
        }
    }

    fn get_active_context_pos(&self, handle: &[u8; HANDLE_SIZE], locality: u32) -> Option<usize> {
        self.contexts.iter().position(|context| {
            context.state == ContextState::Active
                && &context.handle == handle
                && context.locality == locality
        })
    }

    fn get_next_inactive_context_pos(&self) -> Option<usize> {
        self.contexts
            .iter()
            .position(|context| context.state == ContextState::Inactive)
    }

    /// Recursive function that will return all of a context's descendants. Returns a u32 that is
    /// a bitmap of the node indices.
    fn get_descendants(&self, context: &Context) -> Result<u32, DpeErrorCode> {
        if matches!(context.state, ContextState::Inactive) {
            return Err(DpeErrorCode::InvalidHandle);
        }

        let mut descendants = context.children;
        for idx in flags_iter(context.children, MAX_HANDLES) {
            descendants |= self.get_descendants(&self.contexts[idx])?;
        }
        Ok(descendants)
    }

    fn generate_new_handle(&self) -> Result<[u8; HANDLE_SIZE], DpeErrorCode> {
        for _ in 0..Self::MAX_NEW_HANDLE_ATTEMPTS {
            let mut handle = [0; HANDLE_SIZE];
            C::rand_bytes(&mut handle).map_err(|_| DpeErrorCode::InternalError)?;
            if handle != Self::DEFAULT_CONTEXT_HANDLE
                && !self.contexts.iter().any(|c| c.handle == handle)
            {
                return Ok(handle);
            }
        }
        Err(DpeErrorCode::InternalError)
    }

    /// Rolls the context handle if the context is not the default context.
    ///
    /// # Arguments
    ///
    /// * `idx` - the index of the context
    fn roll_onetime_use_handle(&mut self, idx: usize) -> Result<(), DpeErrorCode> {
        if idx >= MAX_HANDLES {
            return Err(DpeErrorCode::InternalError);
        }
        if self.contexts[idx].handle != Self::DEFAULT_CONTEXT_HANDLE {
            self.contexts[idx].handle = self.generate_new_handle()?
        };
        Ok(())
    }

    /// Get the TCI nodes from `context` to the root node following parent
    /// links. These are the nodes that should contribute to CDI and key
    /// derivation for `context`.
    ///
    /// Returns the number of TCIs written to `nodes`
    fn get_tcb_nodes(
        &self,
        context: &Context,
        nodes: &mut [TciNodeData],
    ) -> Result<usize, DpeErrorCode> {
        let mut curr = context;
        let mut out_idx = 0;

        loop {
            if out_idx >= nodes.len() || curr.state != ContextState::Active {
                return Err(DpeErrorCode::InternalError);
            }

            // TODO: The root node isn't a real node with measurements and
            // shouldn't be in the cert. But we don't support DeriveChild yet,
            // so this is the only node we can create to test cert creation.
            nodes[out_idx] = curr.tci;
            out_idx += 1;

            // Found the root
            if curr.parent_idx == 0xFF {
                break;
            }

            curr = &self.contexts[curr.parent_idx as usize];
        }

        Ok(out_idx)
    }
}

struct BufWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> Result<(), Error> {
        if s.len() > self.buf.len().saturating_sub(self.offset) {
            return Err(Error::default());
        }

        self.buf[self.offset..self.offset + s.len()].copy_from_slice(s.as_bytes());
        self.offset += s.len();

        Ok(())
    }
}

impl BufWriter<'_> {
    fn write_hex_str(&mut self, src: &[u8]) -> Result<(), DpeErrorCode> {
        for &b in src {
            write!(self, "{b:02x}").map_err(|_| DpeErrorCode::InternalError)?;
        }

        Ok(())
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct TciMeasurement(pub [u8; DPE_PROFILE.get_tci_size()]);

impl Default for TciMeasurement {
    fn default() -> Self {
        Self([0; DPE_PROFILE.get_tci_size()])
    }
}

#[derive(Default)]
pub struct Support {
    pub simulation: bool,
    pub extend_tci: bool,
    pub auto_init: bool,
    pub tagging: bool,
    pub rotate_context: bool,
    pub certify_key: bool,
    pub certify_csr: bool,
    pub internal_info: bool,
    pub internal_dice: bool,
}

impl Support {
    /// Returns all the flags bit-wise OR'ed together in the same configuration as the `GetProfile`
    /// command.
    pub fn get_flags(&self) -> u32 {
        self.get_simulation_flag()
            | self.get_extend_tci_flag()
            | self.get_auto_init_flag()
            | self.get_tagging_flag()
            | self.get_rotate_context_flag()
            | self.get_certify_key_flag()
            | self.get_certify_csr_flag()
            | self.get_internal_info_flag()
            | self.get_internal_dice_flag()
    }
    fn get_simulation_flag(&self) -> u32 {
        u32::from(self.simulation) << 31
    }
    fn get_extend_tci_flag(&self) -> u32 {
        u32::from(self.extend_tci) << 30
    }
    fn get_auto_init_flag(&self) -> u32 {
        u32::from(self.auto_init) << 29
    }
    fn get_tagging_flag(&self) -> u32 {
        u32::from(self.tagging) << 28
    }
    fn get_rotate_context_flag(&self) -> u32 {
        u32::from(self.rotate_context) << 27
    }
    fn get_certify_key_flag(&self) -> u32 {
        u32::from(self.certify_key) << 26
    }
    fn get_certify_csr_flag(&self) -> u32 {
        u32::from(self.certify_csr) << 25
    }
    fn get_internal_info_flag(&self) -> u32 {
        u32::from(self.internal_info) << 24
    }
    fn get_internal_dice_flag(&self) -> u32 {
        u32::from(self.internal_dice) << 23
    }
}

#[repr(C, align(4))]
#[derive(Default, Copy, Clone)]
pub(crate) struct TciNodeData {
    pub tci_type: u32,

    // Bits
    // 31: INTERNAL
    // 30-0: Reserved. Must be zero
    flags: u32,
    pub tci_cumulative: TciMeasurement,
    pub tci_current: TciMeasurement,
}

impl TciNodeData {
    const INTERNAL_FLAG_MASK: u32 = 1 << 31;

    pub const fn flag_is_internal(&self) -> bool {
        self.flags & Self::INTERNAL_FLAG_MASK != 0
    }

    fn _set_flag_is_internal(&mut self, value: bool) {
        _set_flag(&mut self.flags, Self::INTERNAL_FLAG_MASK, value);
    }

    pub const fn new() -> TciNodeData {
        TciNodeData {
            tci_type: 0,
            flags: 0,
            tci_cumulative: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
            tci_current: TciMeasurement([0; DPE_PROFILE.get_tci_size()]),
        }
    }

    fn serialize(&self, dst: &mut [u8]) -> Result<usize, DpeErrorCode> {
        if dst.len() < size_of::<Self>() {
            return Err(DpeErrorCode::InternalError);
        }

        let mut offset: usize = 0;
        dst[offset..offset + size_of::<u32>()].copy_from_slice(&self.tci_type.to_le_bytes());
        offset += size_of::<u32>();
        dst[offset..offset + self.tci_cumulative.0.len()].copy_from_slice(&self.tci_cumulative.0);
        offset += self.tci_cumulative.0.len();
        dst[offset..offset + self.tci_current.0.len()].copy_from_slice(&self.tci_current.0);
        offset += self.tci_current.0.len();

        Ok(offset)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ContextState {
    /// Inactive or uninitialized.
    Inactive,
    /// Context is initialized and ready to be used.
    Active,
}

#[derive(Debug, PartialEq, Eq)]
enum ContextType {
    /// Typical context.
    Normal,
    /// Has limitations on what operations can be done.
    Simulation,
}

#[repr(C, align(4))]
struct Context {
    handle: [u8; HANDLE_SIZE],
    tci: TciNodeData,
    /// Bitmap of the node indices that are children of this node
    children: u32,
    /// Index in DPE instance of the parent context. 0xFF if this node is the root
    parent_idx: u8,
    context_type: ContextType,
    state: ContextState,
    /// Which hardware locality owns the context.
    locality: u32,
    /// Whether a tag has been assigned to the context.
    has_tag: bool,
    /// Optional tag assigned to the context.
    tag: u32,
}

impl Context {
    pub const ROOT_INDEX: u8 = 0xff;

    const fn new() -> Context {
        Context {
            handle: [0; HANDLE_SIZE],
            tci: TciNodeData::new(),
            children: 0,
            parent_idx: Self::ROOT_INDEX,
            context_type: ContextType::Normal,
            state: ContextState::Inactive,
            locality: 0,
            has_tag: false,
            tag: 0,
        }
    }

    /// Resets all values to a freshly initialized state.
    ///
    /// # Arguments
    ///
    /// * `context_type` - Context type this will become.
    /// * `locality` - Which hardware locality owns the context.
    /// * `handle` - Value that will be used to refer to the context. Random value for simulation
    ///   contexts and 0x0 for the default context.
    pub fn activate(
        &mut self,
        context_type: ContextType,
        locality: u32,
        handle: &[u8; HANDLE_SIZE],
    ) {
        self.handle.copy_from_slice(handle);
        self.tci = TciNodeData::new();
        self.children = 0;
        self.parent_idx = Self::ROOT_INDEX;
        self.context_type = context_type;
        self.state = ContextState::Active;
        self.locality = locality;
    }

    /// Destroy this context so it can no longer be used until it is re-initialized. The default
    /// context cannot be re-initialized.
    pub fn destroy(&mut self) {
        self.tci = TciNodeData::new();
        self.has_tag = false;
        self.tag = 0;
        self.state = ContextState::Inactive;
    }
}

/// Iterate over all of the bits set to 1 in a u32. Each iteration returns the bit index 0 being the
/// least significant.
///
/// # Arguments
///
/// * `flags` - bits to be iterated over
/// * `max` - number of bits to be considered
fn flags_iter(flags: u32, max: usize) -> FlagsIter {
    assert!((1..=u32::BITS).contains(&(max as u32)));
    FlagsIter {
        flags: flags & (u32::MAX >> (u32::BITS - max as u32)),
    }
}

struct FlagsIter {
    flags: u32,
}

impl Iterator for FlagsIter {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.flags == 0 {
            return None;
        }
        let idx = self.flags.trailing_zeros() as usize;
        self.flags &= !(1 << idx);
        Some(idx)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::DpeProfile;
    use crate::{commands::CommandHdr, CURRENT_PROFILE_VERSION};
    use crypto::OpensslCrypto;
    use x509_parser::nom::Parser;
    use x509_parser::prelude::X509CertificateParser;
    use x509_parser::prelude::*;
    use zerocopy::AsBytes;

    const SUPPORT: Support = Support {
        simulation: true,
        extend_tci: false,
        auto_init: true,
        tagging: true,
        rotate_context: true,
        certify_key: true,
        certify_csr: false,
        internal_info: false,
        internal_dice: false,
    };
    pub const TEST_HANDLE: [u8; HANDLE_SIZE] =
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    pub const SIMULATION_HANDLE: [u8; HANDLE_SIZE] =
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    pub const TEST_LOCALITIES: [u32; 2] = [
        DpeInstance::<OpensslCrypto>::AUTO_INIT_LOCALITY,
        u32::from_be_bytes(*b"OTHR"),
    ];

    #[test]
    fn test_localities() {
        // Empty list of localities.
        assert_eq!(
            DpeErrorCode::InvalidLocality,
            DpeInstance::<OpensslCrypto>::new(SUPPORT, &[])
                .err()
                .unwrap()
        );

        // Auto-init without the auto-init locality.
        assert_eq!(
            DpeErrorCode::InvalidLocality,
            DpeInstance::<OpensslCrypto>::new(SUPPORT, &TEST_LOCALITIES[1..])
                .err()
                .unwrap()
        );

        let mut dpe = DpeInstance::<OpensslCrypto>::new(SUPPORT, &TEST_LOCALITIES).unwrap();
        assert_eq!(
            Err(DpeErrorCode::InvalidLocality),
            dpe.execute_serialized_command(
                0x1234_5678, // test value that is not part of the localities
                CommandHdr::new(Command::GetProfile).as_bytes(),
            )
        );

        // Make sure requests work for all localities.
        for l in TEST_LOCALITIES {
            assert_eq!(
                Response::GetProfile(GetProfileResp::new(SUPPORT.get_flags())),
                dpe.execute_serialized_command(l, CommandHdr::new(Command::GetProfile).as_bytes())
                    .unwrap()
            );
        }

        // Initialize a context to run some tests against.
        dpe.initialize_context(TEST_LOCALITIES[1], &InitCtxCmd::new_simulation())
            .unwrap();

        // Make sure the locality was recorded correctly.
        assert_eq!(
            dpe.contexts[dpe
                .get_active_context_pos(&SIMULATION_HANDLE, TEST_LOCALITIES[1])
                .unwrap()]
            .locality,
            TEST_LOCALITIES[1]
        );

        // Make sure the other locality can't destroy it.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            dpe.destroy_context(
                TEST_LOCALITIES[0],
                &DestroyCtxCmd {
                    handle: SIMULATION_HANDLE,
                    flags: 0
                }
            )
        );

        // Make sure right locality can destroy it.
        assert!(dpe
            .destroy_context(
                TEST_LOCALITIES[1],
                &DestroyCtxCmd {
                    handle: SIMULATION_HANDLE,
                    flags: 0,
                },
            )
            .is_ok());
    }

    #[test]
    fn test_execute_serialized_command() {
        let mut dpe = DpeInstance::<OpensslCrypto>::new(SUPPORT, &TEST_LOCALITIES).unwrap();

        assert_eq!(
            Response::GetProfile(GetProfileResp::new(SUPPORT.get_flags())),
            dpe.execute_serialized_command(
                TEST_LOCALITIES[0],
                CommandHdr::new(Command::GetProfile).as_bytes(),
            )
            .unwrap()
        );

        // The default context was initialized while creating the instance. Now lets create a
        // simulation context.
        let mut command = CommandHdr::new(Command::InitCtx(InitCtxCmd::new_simulation()))
            .as_bytes()
            .to_vec();
        command.extend(InitCtxCmd::new_simulation().as_bytes());
        assert_eq!(
            Response::InitCtx(NewHandleResp {
                handle: SIMULATION_HANDLE
            }),
            dpe.execute_serialized_command(TEST_LOCALITIES[0], &command)
                .unwrap()
        );
    }

    #[test]
    fn test_get_profile() {
        let dpe = DpeInstance::<OpensslCrypto>::new(SUPPORT, &TEST_LOCALITIES).unwrap();
        let profile = dpe.get_profile().unwrap();
        assert_eq!(profile.version, CURRENT_PROFILE_VERSION);
        assert_eq!(profile.flags, SUPPORT.get_flags());
    }

    #[test]
    fn test_initialize_context() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();

        // Make sure default context is 0x0.
        assert_eq!(
            DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
            dpe.initialize_context(TEST_LOCALITIES[0], &InitCtxCmd::new_use_default())
                .unwrap()
                .handle
        );

        // Try to double initialize the default context.
        assert_eq!(
            DpeErrorCode::ArgumentNotSupported,
            dpe.initialize_context(TEST_LOCALITIES[0], &InitCtxCmd::new_use_default())
                .err()
                .unwrap()
        );

        // Try not setting any flags.
        assert_eq!(
            DpeErrorCode::InvalidArgument,
            dpe.initialize_context(TEST_LOCALITIES[0], &InitCtxCmd { flags: 0 })
                .err()
                .unwrap()
        );

        // Try simulation when not supported.
        assert_eq!(
            DpeErrorCode::ArgumentNotSupported,
            dpe.initialize_context(TEST_LOCALITIES[0], &InitCtxCmd::new_simulation())
                .err()
                .unwrap()
        );

        // Change to support simulation.
        let mut dpe = DpeInstance::<OpensslCrypto>::new(
            Support {
                simulation: true,
                ..Support::default()
            },
            &TEST_LOCALITIES,
        )
        .unwrap();

        // Try setting both flags.
        assert_eq!(
            DpeErrorCode::InvalidArgument,
            dpe.initialize_context(TEST_LOCALITIES[0], &InitCtxCmd { flags: 3 << 30 })
                .err()
                .unwrap()
        );

        // Set all handles as active.
        for context in dpe.contexts.iter_mut() {
            context.state = ContextState::Active;
        }

        // Try to initialize a context when it is full.
        assert_eq!(
            DpeErrorCode::MaxTcis,
            dpe.initialize_context(TEST_LOCALITIES[0], &InitCtxCmd::new_simulation())
                .err()
                .unwrap()
        );
    }

    #[test]
    fn test_rotate_context() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();
        // Make sure it returns an error if the command is marked unsupported.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            dpe.rotate_context(
                TEST_LOCALITIES[0],
                &RotateCtxCmd {
                    handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                    flags: 0,
                    target_locality: 0
                }
            )
        );

        // Make a new instance that supports RotateContext.
        let mut dpe = DpeInstance::<OpensslCrypto>::new(
            Support {
                rotate_context: true,
                ..Support::default()
            },
            &TEST_LOCALITIES,
        )
        .unwrap();
        dpe.initialize_context(TEST_LOCALITIES[0], &InitCtxCmd::new_use_default())
            .unwrap();

        // Invalid handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            dpe.rotate_context(
                TEST_LOCALITIES[0],
                &RotateCtxCmd {
                    handle: TEST_HANDLE,
                    flags: 0,
                    target_locality: 0
                }
            )
        );

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            dpe.rotate_context(
                TEST_LOCALITIES[1],
                &RotateCtxCmd {
                    handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                    flags: 0,
                    target_locality: 0
                }
            )
        );

        // Rotate default handle.
        assert_eq!(
            Ok(Response::RotateCtx(NewHandleResp {
                handle: SIMULATION_HANDLE
            })),
            dpe.rotate_context(
                TEST_LOCALITIES[0],
                &RotateCtxCmd {
                    handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                    flags: 0,
                    target_locality: 0
                }
            )
        );
    }

    #[test]
    fn test_certify_key() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();

        let init_resp = dpe
            .initialize_context(TEST_LOCALITIES[0], &InitCtxCmd::new_use_default())
            .unwrap();
        let certify_cmd = CertifyKeyCmd {
            handle: init_resp.handle,
            flags: 0,
            label: [0; DPE_PROFILE.get_hash_size()],
        };

        let certify_resp = dpe.certify_key(TEST_LOCALITIES[0], &certify_cmd).unwrap();
        assert_ne!(certify_resp.cert_size, 0);

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(false);
        match parser.parse(&certify_resp.cert[..certify_resp.cert_size.try_into().unwrap()]) {
            Ok((_, cert)) => {
                assert_eq!(cert.version(), X509Version::V3);
            }
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };
    }

    #[test]
    fn test_get_support_flags() {
        // Supports simulation flag.
        let flags = Support {
            simulation: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 31);
        // Supports extended TCI flag.
        let flags = Support {
            extend_tci: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 30);
        // Supports auto-init.
        let flags = Support {
            auto_init: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 29);
        // Supports tagging.
        let flags = Support {
            tagging: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 28);
        // Supports rotate context.
        let flags = Support {
            rotate_context: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 27);
        // Supports certify key.
        let flags = Support {
            certify_key: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 26);
        // Supports certify csr.
        let flags = Support {
            certify_csr: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 25);
        // Supports internal info.
        let flags = Support {
            internal_info: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 24);
        // Supports internal DICE.
        let flags = Support {
            internal_dice: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, 1 << 23);
        // Supports a couple combos.
        let flags = Support {
            simulation: true,
            auto_init: true,
            rotate_context: true,
            certify_csr: true,
            internal_dice: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 31) | (1 << 29) | (1 << 27) | (1 << 25) | (1 << 23)
        );
        let flags = Support {
            extend_tci: true,
            tagging: true,
            certify_key: true,
            internal_info: true,
            ..Support::default()
        }
        .get_flags();
        assert_eq!(flags, (1 << 30) | (1 << 28) | (1 << 26) | (1 << 24));
        // Supports everything.
        let flags = Support {
            simulation: true,
            extend_tci: true,
            auto_init: true,
            tagging: true,
            rotate_context: true,
            certify_key: true,
            certify_csr: true,
            internal_info: true,
            internal_dice: true,
        }
        .get_flags();
        assert_eq!(
            flags,
            (1 << 31)
                | (1 << 30)
                | (1 << 29)
                | (1 << 28)
                | (1 << 27)
                | (1 << 26)
                | (1 << 25)
                | (1 << 24)
                | (1 << 23)
        );
    }

    #[test]
    fn test_get_active_context_index() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();
        let expected_index = 7;
        dpe.contexts[expected_index]
            .handle
            .copy_from_slice(&SIMULATION_HANDLE);

        let locality = DpeInstance::<OpensslCrypto>::AUTO_INIT_LOCALITY;
        // Has not been activated.
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_none());

        // Mark it active, but check the wrong locality.
        let locality = 2;
        dpe.contexts[expected_index].state = ContextState::Active;
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .is_none());

        // Should find it now.
        dpe.contexts[expected_index].locality = locality;
        let idx = dpe
            .get_active_context_pos(&SIMULATION_HANDLE, locality)
            .unwrap();
        assert_eq!(expected_index, idx);
    }

    #[test]
    fn test_extend_tci() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();
        // Make sure it returns an error if the command is marked unsupported.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            dpe.extend_tci(
                TEST_LOCALITIES[0],
                &ExtendTciCmd {
                    handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                    data: [0; DPE_PROFILE.get_hash_size()],
                }
            )
        );

        // Turn on support.
        dpe.support.extend_tci = true;
        dpe.initialize_context(TEST_LOCALITIES[0], &InitCtxCmd::new_use_default())
            .unwrap();

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            dpe.extend_tci(
                TEST_LOCALITIES[1],
                &ExtendTciCmd {
                    handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                    data: [0; DPE_PROFILE.get_hash_size()],
                }
            )
        );

        let locality = DpeInstance::<OpensslCrypto>::AUTO_INIT_LOCALITY;
        let default_handle = DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE;
        let handle = dpe.contexts[dpe
            .get_active_context_pos(&default_handle, locality)
            .unwrap()]
        .handle;
        let data = [1; DPE_PROFILE.get_hash_size()];
        dpe.extend_tci(
            TEST_LOCALITIES[0],
            &ExtendTciCmd {
                handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                data,
            },
        )
        .unwrap();

        // Make sure extending the default TCI doesn't change the handle.
        let default_context = &dpe.contexts[dpe
            .get_active_context_pos(&default_handle, locality)
            .unwrap()];
        assert_eq!(handle, default_context.handle);
        // Make sure the current TCI was updated correctly.
        assert_eq!(data, default_context.tci.tci_current.0);

        let md = match DPE_PROFILE {
            DpeProfile::P256Sha256 => openssl::hash::MessageDigest::sha256(),
            DpeProfile::P384Sha384 => openssl::hash::MessageDigest::sha384(),
        };
        let mut hasher = openssl::hash::Hasher::new(md).unwrap();

        // Add the default TCI.
        hasher.update(&[0; DPE_PROFILE.get_hash_size()]).unwrap();
        hasher.update(&data).unwrap();
        let first_cumulative = hasher.finish().unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(
            first_cumulative.as_ref(),
            default_context.tci.tci_cumulative.0
        );

        let data = [2; DPE_PROFILE.get_hash_size()];
        dpe.extend_tci(
            TEST_LOCALITIES[0],
            &ExtendTciCmd {
                handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                data,
            },
        )
        .unwrap();
        // Make sure the current TCI was updated correctly.
        let default_context = &dpe.contexts[dpe
            .get_active_context_pos(&default_handle, locality)
            .unwrap()];
        assert_eq!(data, default_context.tci.tci_current.0);

        let mut hasher = openssl::hash::Hasher::new(md).unwrap();
        hasher.update(&first_cumulative).unwrap();
        hasher.update(&data).unwrap();
        let second_cumulative = hasher.finish().unwrap();

        // Make sure the cumulative was computed correctly.
        assert_eq!(
            second_cumulative.as_ref(),
            default_context.tci.tci_cumulative.0
        );

        let sim_local = TEST_LOCALITIES[1];
        dpe.support.simulation = true;
        dpe.initialize_context(sim_local, &InitCtxCmd::new_simulation())
            .unwrap();

        // Give the simulation context another handle so we can prove the handle rotates when it
        // gets extended.
        let simulation_ctx = &mut dpe.contexts[dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .unwrap()];
        let sim_tmp_handle = [0xff; HANDLE_SIZE];
        simulation_ctx.handle = sim_tmp_handle;
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .is_none());

        dpe.extend_tci(
            TEST_LOCALITIES[1],
            &ExtendTciCmd {
                handle: sim_tmp_handle,
                data,
            },
        )
        .unwrap();
        // Make sure it rotated back to the deterministic simulation handle.
        assert!(dpe
            .get_active_context_pos(&sim_tmp_handle, sim_local)
            .is_none());
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .is_some());
    }

    #[test]
    fn test_tag_tci() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();
        // Make sure it returns an error if the command is marked unsupported.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            dpe.tag_tci(
                TEST_LOCALITIES[0],
                &TagTciCmd {
                    handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                    tag: 0,
                }
            )
        );

        // Make a new instance that supports tagging.
        let mut dpe = DpeInstance::<OpensslCrypto>::new(
            Support {
                tagging: true,
                simulation: true,
                ..Support::default()
            },
            &TEST_LOCALITIES,
        )
        .unwrap();
        dpe.initialize_context(TEST_LOCALITIES[0], &InitCtxCmd::new_use_default())
            .unwrap();
        let sim_local = TEST_LOCALITIES[1];
        // Make a simulation context to test against.
        dpe.initialize_context(sim_local, &InitCtxCmd::new_simulation())
            .unwrap();

        // Invalid handle.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            dpe.tag_tci(
                TEST_LOCALITIES[0],
                &TagTciCmd {
                    handle: TEST_HANDLE,
                    tag: 0,
                }
            )
        );

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            dpe.tag_tci(
                TEST_LOCALITIES[1],
                &TagTciCmd {
                    handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                    tag: 0,
                }
            )
        );

        // Tag default handle.
        assert_eq!(
            Ok(Response::TagTci(NewHandleResp {
                handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
            })),
            dpe.tag_tci(
                TEST_LOCALITIES[0],
                &TagTciCmd {
                    handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                    tag: 0,
                }
            )
        );

        // Try to re-tag the default context.
        assert_eq!(
            Err(DpeErrorCode::BadTag),
            dpe.tag_tci(
                TEST_LOCALITIES[0],
                &TagTciCmd {
                    handle: DpeInstance::<OpensslCrypto>::DEFAULT_CONTEXT_HANDLE,
                    tag: 1,
                }
            )
        );

        // Try same tag on simulation.
        assert_eq!(
            Err(DpeErrorCode::BadTag),
            dpe.tag_tci(
                TEST_LOCALITIES[1],
                &TagTciCmd {
                    handle: SIMULATION_HANDLE,
                    tag: 0,
                }
            )
        );

        // Give the simulation context another handle so we can prove the handle rotates when it
        // gets tagged.
        let simulation_ctx = &mut dpe.contexts[dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .unwrap()];
        let sim_tmp_handle = [0xff; HANDLE_SIZE];
        simulation_ctx.handle = sim_tmp_handle;
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .is_none());

        // Tag simulation.
        assert_eq!(
            Ok(Response::TagTci(NewHandleResp {
                handle: SIMULATION_HANDLE,
            })),
            dpe.tag_tci(
                TEST_LOCALITIES[1],
                &TagTciCmd {
                    handle: sim_tmp_handle,
                    tag: 1,
                }
            )
        );
        // Make sure it rotated back to the deterministic simulation handle.
        assert!(dpe
            .get_active_context_pos(&sim_tmp_handle, sim_local)
            .is_none());
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .is_some());
    }

    #[test]
    fn test_get_descendants() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();
        let root = 7;
        let child_1 = 3;
        let child_1_1 = 0;
        let child_1_2 = MAX_HANDLES - 1;
        let child_1_2_1 = 1;
        let child_1_3 = MAX_HANDLES - 2;

        // Root isn't active.
        assert_eq!(
            dpe.get_descendants(&dpe.contexts[root]),
            Err(DpeErrorCode::InvalidHandle)
        );

        // No children.
        dpe.contexts[root].state = ContextState::Active;
        assert_eq!(dpe.get_descendants(&dpe.contexts[root]).unwrap(), 0);

        // Child not active.
        dpe.contexts[root].children = 1 << child_1;
        assert_eq!(
            dpe.get_descendants(&dpe.contexts[root]),
            Err(DpeErrorCode::InvalidHandle)
        );

        // One child.
        dpe.contexts[child_1].state = ContextState::Active;
        let mut children = dpe.contexts[root].children;
        assert_eq!(children, dpe.get_descendants(&dpe.contexts[root]).unwrap());

        // Add grandchildren.
        dpe.contexts[child_1_1].state = ContextState::Active;
        dpe.contexts[child_1_2].state = ContextState::Active;
        dpe.contexts[child_1_3].state = ContextState::Active;
        dpe.contexts[child_1].children = (1 << child_1_1) | (1 << child_1_2) | (1 << child_1_3);
        children |= dpe.contexts[child_1].children;
        assert_eq!(children, dpe.get_descendants(&dpe.contexts[root]).unwrap());

        // Add great-grandchildren.
        dpe.contexts[child_1_2_1].state = ContextState::Active;
        dpe.contexts[child_1_2].children = 1 << child_1_2_1;
        children |= dpe.contexts[child_1_2].children;
        assert_eq!(
            dpe.contexts[child_1_2].children,
            dpe.get_descendants(&dpe.contexts[child_1_2]).unwrap()
        );
        assert_eq!(children, dpe.get_descendants(&dpe.contexts[root]).unwrap());
    }
}
