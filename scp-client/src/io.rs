use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use std::{io, path::Path};

use crate::Stream;

pub const BUFFER_SIZE: usize = 8192;
pub const BUFFER_SIZE_U64: u64 = BUFFER_SIZE as u64;

pub async fn send_file(stream: &mut Stream, path: &Path) -> io::Result<()> {
    let mut file = File::open(path).await?;
    let file_size = file.metadata().await?.len();

    stream.write_all(&file_size.to_be_bytes()).await?;
    stream.flush().await?;

    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        stream.write_all(&buffer[..n]).await?;
    }

    stream.flush().await?;
    Ok(())
}

// We pass file_name and output_path because output_path may be a directory.
// In that scenario, we append file_name to output_path.
pub async fn receive_file(
    stream: &mut Stream,
    output_path: &Path,
    file_name: &str,
    file_size: u64,
) -> io::Result<()> {
    let output_path =
        if tokio::fs::metadata(output_path).await.is_ok_and(|m| m.is_dir()) {
            output_path.join(file_name)
        } else {
            output_path.to_path_buf()
        };

    let mut file = File::create(output_path).await?;
    let mut remaining = file_size;
    let mut buffer = [0u8; BUFFER_SIZE];

    while remaining > 0 {
        let to_read = remaining.min(BUFFER_SIZE_U64) as usize;
        let n = stream.read(&mut buffer[..to_read]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection was aborted prematurely",
            ));
        }
        file.write_all(&buffer[..n]).await?;
        remaining -= n as u64;
    }

    file.flush().await?;
    Ok(())
}
