#![feature(never_type)]
mod args;
mod io;
mod session;

use std::{ffi::OsStr, path::Path};

use libssh0::{
    common::{ScpStatus, SessionType},
    read, read_exact, timeout,
};
use libssh0_client::{Res, authenticate, connect_tls, load_private_key};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::client::TlsStream;

use crate::{
    args::{Args, parse_args},
    io::{receive_file, send_file},
    session::Session,
};

type Stream = TlsStream<TcpStream>;

#[tokio::main(worker_threads = 1)]
async fn main() -> Res<()> {
    let Args { source, destination, port, key_path } = parse_args()?;
    let Session {
        session_type,
        host,
        source_path,
        destination_path,
        file_name,
    } = session::define_session_type(source, destination)?;

    let private_key = load_private_key(key_path)?;

    let mut stream = connect_tls(&host, port).await?;

    timeout(authenticate(&mut stream, private_key, session_type)).await??;

    match session_type {
        SessionType::Upload => {
            upload(
                stream,
                &source_path,
                destination_path.as_os_str(),
                &file_name,
            )
            .await
        }
        SessionType::Download => {
            download(
                stream,
                source_path.as_os_str(),
                &destination_path,
                &file_name,
            )
            .await
        }
        SessionType::Shell => unreachable!(),
    }
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

    if let Err(error) = send_file(&mut stream, source).await {
        eprintln!("Local error: {error}");
        read_error(&mut stream).await?;
    }

    recv_success(&mut stream).await?;
    println!("Success!");
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

    if let Err(error) =
        receive_file(&mut stream, destination, file_name, remote_file_size)
            .await
    {
        eprintln!("Local error: {error}");
        read_error(&mut stream).await?;
    }

    recv_success(&mut stream).await?;
    println!("Success!");

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
