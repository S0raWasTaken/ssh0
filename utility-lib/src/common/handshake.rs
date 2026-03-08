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
    print_banner: bool,
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

    if print_banner {
        println!();
        println!("\x1b[1;31m░█░█░░█░█░█░ PRAISE THE CODE! ░█░█░░█░█░█░\x1b[0m");
        println!();
    }

    stream.write_all(&session_type.to_byte()).await?;
    Ok(())
}
