use crate::{
    Stream,
    args::FileInfo,
    io::{receive_file, send_file},
};
use indicatif::MultiProgress;
use libssh0::{
    Res,
    common::scp::{ClientProbeMessage, ScpStatus},
    read, read_exact,
};
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};
use tokio::io::AsyncWriteExt;

pub async fn probe_parse_glob(
    mut stream: Stream,
    path: PathBuf,
) -> Res<Vec<FileInfo>> {
    stream.write_all(&ClientProbeMessage::Glob.to_byte()).await?;
    send_path(&mut stream, path.as_os_str()).await?;

    match recv_any(&mut stream).await? {
        ScpStatus::Continue => (), // Continue
        ScpStatus::Success => return Ok(Vec::new()), // Empty directory
        ScpStatus::Error => unreachable!(),
    }

    let entries_len =
        u32::from_be_bytes(read_exact!(stream, 4).await?) as usize;
    let mut entries = Vec::new();

    for _ in 0..entries_len {
        let entry_len =
            u32::from_be_bytes(read_exact!(stream, 4).await?) as usize;
        let entry = String::from_utf8(read!(stream, entry_len).await?)?;
        let path = PathBuf::from(entry);
        entries.push(FileInfo {
            path: path.clone(),
            name: path
                .file_name()
                .ok_or("This shouldn't happen ever")?
                .to_string_lossy()
                .to_string(),
        });
        recv_ok(&mut stream).await?;
    }

    recv_success(&mut stream).await?;
    Ok(entries)
}

// Client -> Server
//
// send [remote output_path size]
// recv     [ok]
// send [remote output_path bytes]
// recv     [ok]
// send [local file_name size]
// recv     [ok]
// send [local file_name bytes]
// recv     [ok]
// send [local file size]    (uncapped, so no ok expected)
// send [local file bytes]
// recv   [success]
pub async fn upload(
    mut stream: Stream,
    source: &Path,
    remote_output: &OsStr,
    file_name: &str,
    multi_progress_bar: MultiProgress,
) -> Res<()> {
    send_path(&mut stream, remote_output).await?;

    // send [local file_name size]
    let local_file_name_size =
        u32::to_be_bytes(u32::try_from(file_name.len())?);

    stream.write_all(&local_file_name_size).await?;
    recv_ok(&mut stream).await?;

    // send [local file_name bytes]
    stream.write_all(file_name.as_bytes()).await?;
    recv_ok(&mut stream).await?;

    if let Err(error) = send_file(&mut stream, source, multi_progress_bar).await
    {
        eprintln!("Local error: {error}");
        read_error(&mut stream).await?;
    }

    recv_success(&mut stream).await?;
    Ok(())
}

// Server -> Client
//
// send [remote file_path size]
// recv     [ok]
// send [remote file_path bytes]
// recv     [ok] (path is valid UTF-8)
// recv     [ok] (path exists)
// recv [remote file size]
// recv [remote file bytes]
// recv   [success]
pub async fn download(
    mut stream: Stream,
    remote_source: &OsStr,
    destination: &Path,
    file_name: &str,
    multi_progress_bar: MultiProgress,
) -> Res<()> {
    send_path(&mut stream, remote_source).await?;
    recv_ok(&mut stream).await?;

    // recv [remote file size]
    let remote_file_size = u64::from_be_bytes(read_exact!(stream, 8).await?);

    if let Err(error) = receive_file(
        &mut stream,
        destination,
        file_name,
        remote_file_size,
        multi_progress_bar,
    )
    .await
    {
        eprintln!("Local error: {error}");
        read_error(&mut stream).await?;
    }

    recv_success(&mut stream).await?;
    Ok(())
}

async fn recv_ok(stream: &mut Stream) -> Res<()> {
    match recv_any(stream).await? {
        ScpStatus::Continue => Ok(()),
        ScpStatus::Success => {
            Err("Success received, but it was unexpected".into())
        }
        ScpStatus::Error => unreachable!(),
    }
}

async fn recv_success(stream: &mut Stream) -> Res<()> {
    match recv_any(stream).await? {
        ScpStatus::Continue => {
            Err("Continue received, but success was expected".into())
        }
        ScpStatus::Success => Ok(()),
        ScpStatus::Error => unreachable!(),
    }
}

async fn recv_any(mut stream: &mut Stream) -> Res<ScpStatus> {
    match ScpStatus::from_byte(read_exact!(stream, 1).await?)
        .ok_or("Invalid status received")?
    {
        ScpStatus::Error => read_error(stream).await?,
        status => Ok(status),
    }
}

async fn send_path(stream: &mut Stream, path: &OsStr) -> Res<()> {
    let remote_output_path_size = u32::to_be_bytes(u32::try_from(path.len())?);
    stream.write_all(&remote_output_path_size).await?;
    recv_ok(stream).await?;
    stream.write_all(path.as_encoded_bytes()).await?;
    recv_ok(stream).await?;
    Ok(())
}

async fn read_error(mut stream: &mut Stream) -> Res<!> {
    let error_length = u32::from_be_bytes(read_exact!(stream, 4).await?);
    let error = read!(stream, error_length as usize).await?;

    eprint!("Remote "); // Will show up as 'Remote Error: etc'
    Err(String::from_utf8(error)?.into())
}
