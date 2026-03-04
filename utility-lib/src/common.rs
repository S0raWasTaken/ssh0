#[repr(u8)]
#[non_exhaustive]
pub enum SessionType {
    Shell = 0x00,
    Upload = 0x01,
    Download = 0x02,
}

impl SessionType {
    #[must_use]
    pub fn from_u8(byte: [u8; 1]) -> Option<Self> {
        match byte[0] {
            0x00 => Some(Self::Shell),
            0x01 => Some(Self::Upload),
            0x02 => Some(Self::Download),
            _ => None,
        }
    }
}

pub const SCP_ERROR: [u8; 1] = [0xFF];
pub const SCP_CONTINUE: [u8; 1] = [0x00];
pub const SCP_SUCCESS: [u8; 1] = [0x01];

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

        println!("\x1b[1;31m░█░█░░█░█░█░ PRAISE THE CODE! ░█░█░░█░█░█░\x1b[0m");

        stream.write_all(&[session_type as u8]).await?;
        Ok(())
    }
}
