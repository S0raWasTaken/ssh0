use crate::Stream;
use crate::sessions::SessionInfo;

use super::{Res, print_err};
use libssh0::DropGuard;
use libssh0::break_if;
use libssh0::common::SshMessage;
use libssh0::log;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::{
    env,
    io::{Read, Write},
};
use tokio::io::ReadHalf;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    select, spawn,
    sync::mpsc::{Receiver, Sender, channel},
    task::spawn_blocking,
};
use tokio_util::sync::CancellationToken;

pub enum PtyMessage {
    Input(Vec<u8>),
    Resize(u16, u16),
}

macro_rules! read_or_cancel {
    ($token:expr, $read:expr) => {
        select! {
            () = $token.cancelled() => break,
            result = $read => {
                break_if!(result.is_err());
            }
        }
    };
}

pub async fn handle_client_connection(
    socket: Stream,
    session: SessionInfo,
) -> Res<Stream> {
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
    let (tcp_rx, tcp_tx) = tokio::io::split(socket);
    let (pty_tx, pty_rx) = channel::<Vec<u8>>(32);

    let mut pty_read = spawn_blocking(move || read_pty(reader, &pty_tx));

    let tcp_tx_handle =
        spawn(forward_to_tcp(pty_rx, tcp_tx, session.token.clone()));

    let (write_tx, write_rx) = channel::<PtyMessage>(32);
    spawn_blocking(move || {
        write_pty(writer, write_rx, pair.master.as_ref());
    });

    let (tcp_msg_tx, mut tcp_msg_rx) = channel::<PtyMessage>(32);
    let mut tcp_read =
        spawn(read_tcp(tcp_rx, tcp_msg_tx, session.token.clone()));

    let mut tcp_rx_result = None;

    loop {
        select! {
            _ = &mut pty_read => {
                log!("{session} closed");
                session.token.cancel();
                break;
            }
            () = session.token.cancelled() => {
                pty_read.abort();
                break;
            }
            result = &mut tcp_read => {
                log!("{session} closed");
                tcp_rx_result = Some(result);
                session.token.cancel();
                break;
            }
            msg = tcp_msg_rx.recv() => match msg {
                Some(msg) => read_or_cancel!(session.token, write_tx.send(msg)),
                None => break,
            }
        }
    }

    session.token.cancel();

    drop(tcp_msg_rx);

    let tcp_rx = match tcp_rx_result {
        Some(result) => result?,
        None => tcp_read.await?,
    };

    Ok(tcp_rx.unsplit(tcp_tx_handle.await?))
}

const MAX_INPUT_FRAME: usize = 1024 * 1024;
async fn read_tcp(
    mut tcp_rx: ReadHalf<Stream>,
    tx: Sender<PtyMessage>,
    token: CancellationToken,
) -> ReadHalf<Stream> {
    loop {
        let mut type_buf = [0u8; 1];

        read_or_cancel!(token, tcp_rx.read_exact(&mut type_buf));

        match SshMessage::from_byte(type_buf) {
            Some(SshMessage::Input) => {
                let mut len_buf = [0u8; 4];
                read_or_cancel!(token, tcp_rx.read_exact(&mut len_buf));
                let len = u32::from_be_bytes(len_buf) as usize;
                break_if!(len > MAX_INPUT_FRAME);
                let mut data = vec![0u8; len];
                read_or_cancel!(token, tcp_rx.read_exact(&mut data));
                read_or_cancel!(token, tx.send(PtyMessage::Input(data)));
            }
            Some(SshMessage::Resize) => {
                let mut buf = [0u8; 4];
                read_or_cancel!(token, tcp_rx.read_exact(&mut buf));
                let cols = u16::from_be_bytes([buf[0], buf[1]]);
                let rows = u16::from_be_bytes([buf[2], buf[3]]);
                read_or_cancel!(token, tx.send(PtyMessage::Resize(cols, rows)));
            }
            _ => break,
        }
    }
    tcp_rx
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

pub fn write_pty(
    mut writer: Box<dyn Write + Send>,
    mut rx: Receiver<PtyMessage>,
    master: &(dyn portable_pty::MasterPty + Send),
) {
    while let Some(msg) = rx.blocking_recv() {
        match msg {
            PtyMessage::Input(data) => {
                if writer.write_all(&data).is_err() {
                    break;
                }
            }
            PtyMessage::Resize(cols, rows) => {
                master
                    .resize(PtySize { cols, rows, ..PtySize::default() })
                    .inspect_err(print_err)
                    .ok();
            }
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
