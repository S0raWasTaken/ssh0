use std::fmt::Display;

use ssh0_proc_macro::{FromByte, ToByte};

#[repr(u8)]
#[derive(Clone, Copy, FromByte, ToByte)]
pub enum SessionType {
    Shell = 0x00,
    Upload = 0x01,
    Download = 0x02,
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
#[derive(FromByte, ToByte)]
pub enum SshMessage {
    Input = 0x00,
    Resize = 0x01,
}

#[repr(u8)]
#[derive(FromByte, ToByte)]
pub enum ScpMessage {
    NextFile = 0x00,
    Done = 0x01,
}

#[repr(u8)]
#[derive(FromByte, ToByte)]
pub enum ScpStatus {
    Continue = 0x00,
    Success = 0x01,
    Error = 0x02,
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

        stream.write_all(&session_type.to_byte()).await?;
        Ok(())
    }
}
