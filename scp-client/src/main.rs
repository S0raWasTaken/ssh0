#![feature(never_type)]
mod args;
mod io;

use std::{ffi::OsStr, path::Path};

use indicatif::MultiProgress;
use libssh0::{
    common::{ScpStatus, SessionType},
    read, read_exact, timeout,
};
use libssh0_client::{
    BoxedError, Res, authenticate, connect_tls, load_private_key,
};
use tokio::{io::AsyncWriteExt, net::TcpStream, task::JoinSet};
use tokio_rustls::client::TlsStream;

use crate::{
    args::{Args, FileInfo},
    io::{receive_file, send_file},
};

type Stream = TlsStream<TcpStream>;

#[tokio::main]
async fn main() -> Res<()> {
    let Args { session_type, source_files, destination, key_path, host, port } =
        Args::from_argh()?;

    let private_key = load_private_key(key_path)?;

    let multi_progress_bar = MultiProgress::new();

    let mut task_set = JoinSet::new();

    let mut print_banner = true;

    for FileInfo { path: file_path, name: file_name } in source_files {
        let private_key = private_key.clone();
        let multi_progress = multi_progress_bar.clone();
        let host = host.clone();
        let destination = destination.clone();

        #[expect(clippy::excessive_nesting)]
        task_set.spawn(async move {
            let mut stream = connect_tls(&host, port).await?;
            timeout(authenticate(
                &mut stream,
                private_key,
                session_type,
                print_banner,
            ))
            .await??;

            match session_type {
                SessionType::Upload => {
                    upload(
                        stream,
                        &file_path,
                        destination.as_os_str(),
                        &file_name,
                        multi_progress,
                    )
                    .await?;
                }
                SessionType::Download => {
                    download(
                        stream,
                        file_path.as_os_str(),
                        &destination,
                        &file_name,
                        multi_progress,
                    )
                    .await?;
                }
                SessionType::Shell => unreachable!(),
            }
            Ok::<(), BoxedError>(())
        });
        print_banner = false;
    }
    multi_progress_bar.set_move_cursor(true);

    while let Some(result) = task_set.join_next().await {
        result??;
    }

    Ok(())
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
async fn upload(
    mut stream: Stream,
    source: &Path,
    remote_output: &OsStr,
    file_name: &str,
    multi_progress_bar: MultiProgress,
) -> Res<()> {
    // send [remote output_path size]
    let remote_output_path_size =
        u32::to_be_bytes(u32::try_from(remote_output.len())?);

    stream.write_all(&remote_output_path_size).await?;
    recv_ok(&mut stream).await?;

    // send [remote output_path bytes]
    stream.write_all(remote_output.as_encoded_bytes()).await?;
    recv_ok(&mut stream).await?;

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
async fn download(
    mut stream: Stream,
    remote_source: &OsStr,
    destination: &Path,
    file_name: &str,
    multi_progress_bar: MultiProgress,
) -> Res<()> {
    // send [remote file_path size]
    let remote_file_path_size =
        u32::to_be_bytes(u32::try_from(remote_source.len())?);

    stream.write_all(&remote_file_path_size).await?;
    recv_ok(&mut stream).await?;

    // send [remote file_path bytes]
    stream.write_all(remote_source.as_encoded_bytes()).await?;
    recv_ok(&mut stream).await?;
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

async fn recv_ok(mut stream: &mut Stream) -> Res<()> {
    match ScpStatus::from_byte(read_exact!(stream, 1).await?)
        .ok_or("Invalid status received")?
    {
        ScpStatus::Continue => Ok(()),
        ScpStatus::Success => {
            Err("Success received, but it was unexpected".into())
        }
        ScpStatus::Error => read_error(stream).await?,
    }
}

async fn recv_success(mut stream: &mut Stream) -> Res<()> {
    match ScpStatus::from_byte(read_exact!(stream, 1).await?)
        .ok_or("Invalid status received")?
    {
        ScpStatus::Continue => {
            Err("Continue received, but success was expected".into())
        }
        ScpStatus::Success => Ok(()),
        ScpStatus::Error => read_error(stream).await?,
    }
}

async fn read_error(mut stream: &mut Stream) -> Res<!> {
    let error_length = u32::from_be_bytes(read_exact!(stream, 4).await?);
    let error = read!(stream, error_length as usize).await?;

    eprint!("Remote "); // Will show up as 'Remote Error: etc'
    Err(String::from_utf8(error)?.into())
}
