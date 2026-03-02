use super::{Res, print_err};
use libssh0::DropGuard;
use libssh0::break_if;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::{
    env,
    io::{Read, Write},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    select, spawn,
    sync::mpsc::{Receiver, Sender, channel},
    task::spawn_blocking,
};
use tokio_util::sync::CancellationToken;

pub async fn handle_client_connection<S>(
    socket: S,
    token: CancellationToken,
) -> Res<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let pty = native_pty_system();
    let pair = pty.openpty(PtySize::default())?;

    let default_shell =
        env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    let mut cmd = CommandBuilder::new(default_shell);
    cmd.env("TERM", env::var("TERM").unwrap_or("xterm-256color".to_string()));

    let child = pair.slave.spawn_command(cmd)?;

    let _guard = DropGuard::new(child, |child| {
        child.kill().inspect_err(print_err).ok();
    });

    drop(pair.slave);
    let reader = pair.master.try_clone_reader()?;
    let writer = pair.master.take_writer()?;
    let (mut tcp_rx, tcp_tx) = tokio::io::split(socket);
    let (pty_tx, pty_rx) = channel::<Vec<u8>>(32);

    let mut pty_read = spawn_blocking(move || read_pty(reader, &pty_tx));

    let fwd_token = CancellationToken::new();
    let tcp_tx_handle =
        spawn(forward_to_tcp(pty_rx, tcp_tx, fwd_token.clone()));

    let (write_tx, write_rx) = channel::<Vec<u8>>(32);
    spawn_blocking(move || write_pty(writer, write_rx));

    let mut buf = [0u8; 1024];
    loop {
        select! {
            _ = &mut pty_read => break,
            () = token.cancelled() => {
                pty_read.abort();
                break;
            },
            result = tcp_rx.read(&mut buf) => {
                let n = result?;
                break_if!(n == 0 || write_tx.send(buf[..n].to_vec()).await.is_err());
            }
        }
    }

    fwd_token.cancel();
    Ok(tcp_rx.unsplit(tcp_tx_handle.await?))
}

pub fn read_pty(mut reader: Box<dyn Read + Send>, tx: &Sender<Vec<u8>>) {
    let mut buf = [0u8; 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                break_if!(tx.blocking_send(buf[..n].to_vec()).is_err());
            }
        }
    }
}

pub fn write_pty(mut writer: Box<dyn Write + Send>, mut rx: Receiver<Vec<u8>>) {
    while let Some(data) = rx.blocking_recv() {
        if writer.write_all(&data).is_err() {
            break;
        }
    }
}

pub async fn forward_to_tcp<S: AsyncWrite>(
    mut rx: Receiver<Vec<u8>>,
    mut tcp_tx: WriteHalf<S>,
    token: CancellationToken,
) -> WriteHalf<S> {
    loop {
        select! {
            () = token.cancelled() => break,
            data = rx.recv() => {
                match data {
                    Some(data) => break_if!(tcp_tx.write_all(&data).await.is_err()),
                    None => break,
                }
            }
        }
    }
    tcp_tx
}
