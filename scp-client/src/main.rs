#![feature(never_type)]
mod args;
mod io;
mod network;

use std::path::PathBuf;

use indicatif::MultiProgress;
use libssh0::{BoxedError, Res, common::SessionType, timeout};
use libssh0_client::{authenticate, connect_tls, load_private_key};
use ssh_key::PrivateKey;
use tokio::{net::TcpStream, task::JoinSet};
use tokio_rustls::client::TlsStream;

use crate::args::Args;

pub type Stream = TlsStream<TcpStream>;

struct Session {
    pub host: String,
    pub port: u16,
    pub source_path: PathBuf,
    pub source_name: String,
    pub destination: PathBuf,
    pub private_key: PrivateKey,
    pub kind: SessionType,
}

#[tokio::main]
async fn main() -> Res<()> {
    let Args { session_type, source_files, destination, key_path, host, port } =
        Args::from_argh()?;

    let private_key = load_private_key(key_path)?;

    let multi_progress_bar = MultiProgress::new();

    let mut task_set = JoinSet::new();

    let mut print_banner = true;

    for source in source_files {
        let multi_progress = multi_progress_bar.clone();

        let session = Session {
            host: host.clone(),
            port,
            source_path: source.path,
            source_name: source.name,
            destination: destination.clone(),
            private_key: private_key.clone(),
            kind: session_type,
        };

        task_set.spawn(file_transfer_session(
            session,
            multi_progress,
            print_banner,
        ));
        print_banner = false;
    }

    multi_progress_bar.set_move_cursor(true);

    while let Some(result) = task_set.join_next().await {
        result??;
    }

    Ok(())
}

async fn file_transfer_session(
    session: Session,
    multi_progress_bar: MultiProgress,
    print_banner: bool,
) -> Res<()> {
    let mut stream = connect_tls(&session.host, session.port).await?;
    timeout(authenticate(
        &mut stream,
        session.private_key,
        session.kind,
        print_banner,
    ))
    .await??;

    match session.kind {
        SessionType::Upload => {
            network::upload(
                stream,
                &session.source_path,
                session.destination.as_os_str(),
                &session.source_name,
                multi_progress_bar,
            )
            .await?;
        }
        SessionType::Download => {
            network::download(
                stream,
                session.source_path.as_os_str(),
                &session.destination,
                &session.source_name,
                multi_progress_bar,
            )
            .await?;
        }
        SessionType::Shell | SessionType::Probe => unreachable!(),
    }
    Ok::<(), BoxedError>(())
}
