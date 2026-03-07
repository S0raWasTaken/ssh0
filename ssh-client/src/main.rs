use crate::{args::Args, read_stdin::read_stdin};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use libssh0::{
    DropGuard, Res, break_if,
    common::{SessionType, SshMessage},
    timeout,
};
use libssh0_client::{authenticate, connect_tls, load_private_key};
use std::{
    io::{ErrorKind::UnexpectedEof, Write, stdout},
    process::exit,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    select, spawn,
    sync::mpsc::{Receiver, Sender, channel},
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

    timeout(authenticate(&mut stream, private_key, SessionType::Shell, true))
        .await??;

    let (mut tcp_rx, tcp_tx) = tokio::io::split(stream);
    let (stdin_tx, stdin_rx) = channel::<ClientEvent>(32);
    let resize_tx = stdin_tx.clone();

    if let Ok((cols, rows)) = crossterm::terminal::size() {
        stdin_tx.send(ClientEvent::Resize(cols, rows)).await.ok();
    }

    spawn_blocking(move || read_stdin(&stdin_tx));
    spawn(resize_watcher(resize_tx));
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

const DEFAULT_SIZE: (u16, u16) = (80, 24);
async fn resize_watcher(resize_tx: Sender<ClientEvent>) {
    let mut last_size = crossterm::terminal::size().unwrap_or(DEFAULT_SIZE);
    loop {
        select! {
            () = resize_tx.closed() => break,
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        if let Ok((columns, rows)) = crossterm::terminal::size()
            && (columns, rows) != last_size
        {
            last_size = (columns, rows);
            break_if!(
                resize_tx
                    .send(ClientEvent::Resize(columns, rows))
                    .await
                    .is_err()
            );
        }
    }
}

enum ClientEvent {
    Input(Vec<u8>),
    Resize(u16, u16),
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "if data.len() > 4GiB, we got bigger problems"
)]
async fn forward_to_server<S: AsyncWrite>(
    mut rx: Receiver<ClientEvent>,
    mut tcp_tx: WriteHalf<S>,
) {
    while let Some(event) = rx.recv().await {
        break_if!(match event {
            ClientEvent::Input(data) => {
                tcp_tx.write_all(&SshMessage::Input.to_byte()).await.is_err()
                    || tcp_tx
                        .write_all(&(data.len() as u32).to_be_bytes())
                        .await
                        .is_err()
                    || tcp_tx.write_all(&data).await.is_err()
            }
            ClientEvent::Resize(columns, rows) => {
                tcp_tx.write_all(&SshMessage::Resize.to_byte()).await.is_err()
                    || tcp_tx.write_all(&columns.to_be_bytes()).await.is_err()
                    || tcp_tx.write_all(&rows.to_be_bytes()).await.is_err()
            }
        });
    }
}
