use std::fmt::Display;

use ssh0_proc_macro::{FromByte, ToByte};

#[cfg(feature = "tokio")]
pub mod handshake;

#[repr(u8)]
#[derive(Clone, Copy, FromByte, ToByte)]
pub enum SessionType {
    Shell = 0x00,
    Upload = 0x01,
    Download = 0x02,
    Probe = 0x03,
}

impl Display for SessionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SessionType::Shell => "Shell",
                SessionType::Upload => "SCP Upload",
                SessionType::Download => "SCP Download",
                SessionType::Probe => "SCP Probe",
            }
        )
    }
}

pub const CHALLENGE_SIZE: usize = 256;

#[repr(u8)]
#[derive(FromByte, ToByte)]
pub enum SshMessage {
    Input = 0x00,
    Resize = 0x01,
}

pub mod scp {
    use ssh0_proc_macro::{FromByte, ToByte};

    pub const SCP_BUFFER_SIZE: usize = 8192;

    #[repr(u8)]
    #[derive(FromByte, ToByte)]
    pub enum ScpStatus {
        Continue = 0x00,
        Success = 0x01,
        Error = 0xFF,
    }

    #[repr(u8)]
    #[derive(FromByte, ToByte)]
    pub enum ClientProbeMessage {
        Glob = 0x00,
    }
}
