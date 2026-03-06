use std::fmt::Display;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum SessionType {
    Shell = 0x00,
    Upload = 0x01,
    Download = 0x02,
}

impl SessionType {
    #[must_use]
    pub fn from_byte(byte: [u8; 1]) -> Option<Self> {
        match byte[0] {
            0x00 => Some(Self::Shell),
            0x01 => Some(Self::Upload),
            0x02 => Some(Self::Download),
            _ => None,
        }
    }
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
            }
        )
    }
}

pub const CHALLENGE_SIZE: usize = 256;
pub const SCP_BUFFER_SIZE: usize = 8192;

#[repr(u8)]
pub enum SshMessage {
    Input = 0x00,
    Resize = 0x01,
}

impl SshMessage {
    #[must_use]
    pub fn from_byte(byte: [u8; 1]) -> Option<Self> {
        match byte[0] {
            0x00 => Some(Self::Input),
            0x01 => Some(Self::Resize),
            _ => None,
        }
    }
}

#[repr(u8)]
pub enum ScpStatus {
    Continue = 0x00,
    Success = 0x01,
    Error = 0xFF,
}

impl ScpStatus {
    #[must_use]
    pub fn from_byte(byte: [u8; 1]) -> Option<Self> {
        match byte[0] {
            0x00 => Some(Self::Continue),
            0x01 => Some(Self::Success),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }
}

#[cfg(feature = "tokio")]
pub mod handshake {
    use std::io::{self, Error, ErrorKind::InvalidData};
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

    use crate::read_exact;

    use super::SessionType;

    pub const KEYGEN: [u8; 6] = *b"Keygen";
    pub const CHURCH: [u8; 6] = *b"Church";
    pub const PRAISE_THE_CODE: [u8; 16] = *b"PRAISE THE CODE!";

    /// Performs the client-side handshake with the server.
    ///
    /// Verifies the server's identity tokens (`Keygen` → `PRAISE THE CODE!`),
    /// then sends the desired [`SessionType`] so the server can prepare
    /// the appropriate handler before authentication begins.
    ///
    /// # Errors
    /// Returns [`InvalidData`](std::io::ErrorKind::InvalidData) if the server
    /// sends unexpected handshake bytes, or an I/O error if the stream fails.
    pub async fn handshake_client(
        mut stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
        session_type: SessionType,
    ) -> io::Result<()> {
        let invalid_handshake = Error::new(InvalidData, "Invalid Handshake");

        let keygen = read_exact!(stream, 6).await?;
        if keygen != KEYGEN {
            return Err(invalid_handshake);
        }

        stream.write_all(&CHURCH).await?;
        let response = read_exact!(stream, 16).await?;

        if response != PRAISE_THE_CODE {
            return Err(invalid_handshake);
        }

        println!();
        println!("\x1b[1;31m░█░█░░█░█░█░ PRAISE THE CODE! ░█░█░░█░█░█░\x1b[0m");
        println!();

        stream.write_all(&[session_type as u8]).await?;
        Ok(())
    }
}
