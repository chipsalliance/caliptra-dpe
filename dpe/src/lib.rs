#![no_std]
pub mod commands;

const MAX_HANDLES: usize = 24;

#[cfg(feature = "dpe_profile_p256_sha256")]
mod profile {
    pub const TCI_SIZE: usize = 32;
    pub const CDI_SIZE: usize = 32;
}

#[cfg(feature = "dpe_profile_p384_sha384")]
mod profile {
    pub const TCI_SIZE: usize = 48;
    pub const CDI_SIZE: usize = 48;
}

pub struct DpeError {
    pub status: u32,
}

/// Execute a DPE command.
/// Returns the number of bytes written to `response`.
pub fn execute_command(
    dpe: &mut commands::DpeInstance,
    cmd: &[u8],
    response: &mut [u8],
) -> Result<usize, DpeError> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

