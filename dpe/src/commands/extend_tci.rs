// Licensed under the Apache-2.0 license.
use super::CommandExecution;
use crate::{
    dpe_instance::{ContextHandle, DpeInstance, TciMeasurement},
    response::{DpeErrorCode, NewHandleResp, Response},
    DPE_PROFILE,
};
use core::mem::size_of;
use crypto::{Crypto, Hasher};

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(zerocopy::AsBytes, zerocopy::FromBytes))]
pub struct ExtendTciCmd {
    handle: ContextHandle,
    data: [u8; DPE_PROFILE.get_hash_size()],
}

impl TryFrom<&[u8]> for ExtendTciCmd {
    type Error = DpeErrorCode;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < size_of::<ExtendTciCmd>() {
            return Err(DpeErrorCode::InvalidArgument);
        }

        Ok(ExtendTciCmd {
            handle: ContextHandle::try_from(raw)?,
            data: raw[ContextHandle::SIZE..ContextHandle::SIZE + DPE_PROFILE.get_hash_size()]
                .try_into()
                .unwrap(),
        })
    }
}

impl<C: Crypto> CommandExecution<C> for ExtendTciCmd {
    fn execute(&self, dpe: &mut DpeInstance<C>, locality: u32) -> Result<Response, DpeErrorCode> {
        // Make sure this command is supported.
        if !dpe.support.extend_tci {
            return Err(DpeErrorCode::InvalidCommand);
        }
        let idx = dpe
            .get_active_context_pos(&self.handle, locality)
            .ok_or(DpeErrorCode::InvalidHandle)?;
        let context = &mut dpe.contexts[idx];

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
            .update(&self.data)
            .map_err(|_| DpeErrorCode::InternalError)?;
        hasher
            .finish(&mut context.tci.tci_cumulative.0)
            .map_err(|_| DpeErrorCode::InternalError)?;

        context.tci.tci_current = TciMeasurement(self.data);
        // Rotate the handle if it isn't the default context.
        dpe.roll_onetime_use_handle(idx)?;
        Ok(Response::ExtendTci(NewHandleResp {
            handle: dpe.contexts[idx].handle,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{tests::TEST_DIGEST, Command, CommandHdr, InitCtxCmd},
        dpe_instance::{
            tests::{SIMULATION_HANDLE, TEST_LOCALITIES},
            Support,
        },
        DpeProfile,
    };
    use crypto::OpensslCrypto;
    use zerocopy::{AsBytes, FromBytes};

    const TEST_EXTEND_TCI_CMD: ExtendTciCmd = ExtendTciCmd {
        handle: SIMULATION_HANDLE,
        data: TEST_DIGEST,
    };

    #[test]
    fn try_from_extend_tci() {
        let command_bytes = TEST_EXTEND_TCI_CMD.as_bytes();
        assert_eq!(
            ExtendTciCmd::read_from_prefix(command_bytes).unwrap(),
            ExtendTciCmd::try_from(command_bytes).unwrap(),
        );
    }

    #[test]
    fn test_deserialize_extend_tci() {
        let mut command = CommandHdr::new(Command::ExtendTci(TEST_EXTEND_TCI_CMD))
            .as_bytes()
            .to_vec();
        command.extend(TEST_EXTEND_TCI_CMD.as_bytes());
        assert_eq!(
            Ok(Command::ExtendTci(TEST_EXTEND_TCI_CMD)),
            Command::deserialize(&command)
        );
    }

    #[test]
    fn test_slice_to_extend_tci() {
        // Test if too small.
        assert_eq!(
            Err(DpeErrorCode::InvalidArgument),
            ExtendTciCmd::try_from([0u8; size_of::<ExtendTciCmd>() - 1].as_slice())
        );

        assert_eq!(
            TEST_EXTEND_TCI_CMD,
            ExtendTciCmd::try_from(TEST_EXTEND_TCI_CMD.as_bytes()).unwrap()
        );
    }

    #[test]
    fn test_extend_tci() {
        let mut dpe =
            DpeInstance::<OpensslCrypto>::new(Support::default(), &TEST_LOCALITIES).unwrap();
        // Make sure it returns an error if the command is marked unsupported.
        assert_eq!(
            Err(DpeErrorCode::InvalidCommand),
            ExtendTciCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_hash_size()],
            }
            .execute(&mut dpe, TEST_LOCALITIES[0])
        );

        // Turn on support.
        dpe.support.extend_tci = true;
        InitCtxCmd::new_use_default()
            .execute(&mut dpe, TEST_LOCALITIES[0])
            .unwrap();

        // Wrong locality.
        assert_eq!(
            Err(DpeErrorCode::InvalidHandle),
            ExtendTciCmd {
                handle: ContextHandle::default(),
                data: [0; DPE_PROFILE.get_hash_size()],
            }
            .execute(&mut dpe, TEST_LOCALITIES[1])
        );

        let locality = DpeInstance::<OpensslCrypto>::AUTO_INIT_LOCALITY;
        let default_handle = ContextHandle::default();
        let handle = dpe.contexts[dpe
            .get_active_context_pos(&default_handle, locality)
            .unwrap()]
        .handle;
        let data = [1; DPE_PROFILE.get_hash_size()];
        ExtendTciCmd {
            handle: ContextHandle::default(),
            data,
        }
        .execute(&mut dpe, TEST_LOCALITIES[0])
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
        ExtendTciCmd {
            handle: ContextHandle::default(),
            data,
        }
        .execute(&mut dpe, TEST_LOCALITIES[0])
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
        InitCtxCmd::new_simulation()
            .execute(&mut dpe, sim_local)
            .unwrap();

        // Give the simulation context another handle so we can prove the handle rotates when it
        // gets extended.
        let simulation_ctx = &mut dpe.contexts[dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .unwrap()];
        let sim_tmp_handle = ContextHandle([0xff; ContextHandle::SIZE]);
        simulation_ctx.handle = sim_tmp_handle;
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .is_none());

        ExtendTciCmd {
            handle: sim_tmp_handle,
            data,
        }
        .execute(&mut dpe, TEST_LOCALITIES[1])
        .unwrap();
        // Make sure it rotated back to the deterministic simulation handle.
        assert!(dpe
            .get_active_context_pos(&sim_tmp_handle, sim_local)
            .is_none());
        assert!(dpe
            .get_active_context_pos(&SIMULATION_HANDLE, sim_local)
            .is_some());
    }
}
