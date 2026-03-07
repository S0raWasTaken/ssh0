#![feature(never_type)] // WHY IS THIS NOT STABLE YET????
use crate::{
    args::Args,
    context::{Context, HostAndPort},
    keypair_auth::authenticate_and_accept_connection,
    rate_limit::RateLimiter,
    sessions::SessionRegistry,
    tls::make_acceptor,
    watcher::watch_authorized_keys,
};
use libssh0::{Res, log};
use ssh_key::PublicKey;
use std::{fmt::Display, fs::create_dir_all, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    spawn,
    sync::Semaphore,
};
use tokio_rustls::server::TlsStream;

pub type Stream = TlsStream<TcpStream>;

mod args;
mod context;
mod keypair_auth;
mod rate_limit;
mod scp;
mod sessions;
mod ssh;
mod tls;
mod watcher;

#[tokio::main(worker_threads = 2)]
async fn main() -> Res<()> {
    let context = setup()?;

    let listener = TcpListener::bind(context.host_and_port.inner()).await?;
    log!("Listening on {}", context.host_and_port);

    context.spawn_rate_limiter_task();

    loop {
        accept_new_connection(&listener, context.clone())
            .await
            .inspect_err(print_err)
            .ok();
    }
}

fn setup() -> Res<Arc<Context>> {
    let args: Args = argh::from_env();
    let Args { host, port, .. } = args;

    let config_dir = args
        .config_dir
        .or_else(dirs::config_dir)
        .map(|dir| dir.join("ssh0-daemon"))
        .ok_or("Couldn't find the config directory.")?;

    create_dir_all(&config_dir)?;

    let sessions = Arc::new(SessionRegistry::new());
    Ok(Context::new(
        make_acceptor(&config_dir)?,
        watch_authorized_keys(&config_dir, sessions.clone())?,
        RateLimiter::new(3, Duration::from_mins(30)),
        Semaphore::new(100),
        HostAndPort::new(host, port),
        sessions,
    ))
}

async fn accept_new_connection(
    listener: &TcpListener,
    context: Arc<Context>,
) -> Res<()> {
    let (mut stream, address) = listener.accept().await?;

    let context = Arc::clone(&context);
    let Ok(permit) = Arc::clone(&context.semaphore).try_acquire_owned() else {
        stream.shutdown().await.ok();
        return Ok(());
    };

    if !context.rate_limiter.is_allowed(address.ip()) {
        stream.shutdown().await.ok();
        return Ok(());
    }

    log!("Sending challenge to {address}");

    spawn(async move {
        let _permit = permit;
        authenticate_and_accept_connection(stream, address, context)
            .await
            .inspect_err(print_err)
    });
    Ok(())
}

#[inline]
#[must_use]
pub fn fingerprint(e: &PublicKey) -> String {
    e.fingerprint(ssh_key::HashAlg::Sha256).to_string()
}

fn print_err<E: Display>(e: &E) {
    log!(e "{e}");
}
