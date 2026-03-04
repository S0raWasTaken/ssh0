use crate::{args::Args, read_stdin::read_stdin};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use libssh0::{DropGuard, break_if, common::SessionType, timeout};
use libssh0_client::{Res, authenticate, connect_tls, load_private_key};
use std::{
    io::{ErrorKind::UnexpectedEof, Write, stdout},
    process::exit,
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    spawn,
    sync::mpsc::{Receiver, channel},
    task::spawn_blocking,
};

mod args;
mod read_stdin;

#[tokio::main(worker_threads = 1)]
async fn main() -> Res<()> {
    let Args { host, port, key_path } = argh::from_env();

    let private_key = load_private_key(key_path)?;

    enable_raw_mode()?;
    let guard = DropGuard::new((), |()| {
        disable_raw_mode().ok();
    });

    let mut stream = connect_tls(&host, port).await?;

    timeout(authenticate(&mut stream, private_key, SessionType::Shell))
        .await??;

    let (mut tcp_rx, tcp_tx) = tokio::io::split(stream);
    let (stdin_tx, stdin_rx) = channel::<Vec<u8>>(32);

    spawn_blocking(move || read_stdin(&stdin_tx));
    spawn(forward_to_server(stdin_rx, tcp_tx));

    let mut buf = [0u8; 1024];
    let mut stdout = stdout().lock();
    loop {
        match tcp_rx.read(&mut buf).await {
            Ok(n) if n > 0 => {
                stdout.write_all(&buf[..n])?;
                stdout.flush()?;
            }
            Err(e) if e.kind() != UnexpectedEof => return Err(e.into()),
            _ => {
                drop(guard);
                exit(0);
            }
        }
    }
}

async fn forward_to_server<S: AsyncWrite>(
    mut rx: Receiver<Vec<u8>>,
    mut tcp_tx: WriteHalf<S>,
) {
    while let Some(data) = rx.recv().await {
        break_if!(tcp_tx.write_all(&data).await.is_err());
    }
}
