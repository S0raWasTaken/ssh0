use super::{Res, print_err};
use crate::{
    BoxedError, connection::handle_client_connection, context::Context,
};
use libssh0::{log, timeout};
use notify::{
    Event, EventKind, RecursiveMode::NonRecursive, Watcher, recommended_watcher,
};
use ssh_key::{PublicKey, SshSig};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, RwLock},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;

pub type AuthorizedKeys = Arc<RwLock<Arc<[PublicKey]>>>;

pub fn watch_authorized_keys(path: &Path) -> Res<AuthorizedKeys> {
    let keys = Arc::new(RwLock::new(load_authorized_keys(path)?.into()));
    let keys_clone = Arc::clone(&keys);

    let auth_keys_path = path.to_path_buf();
    let mut watcher =
        recommended_watcher(move |event: notify::Result<Event>| {
            let Ok(event) = event else { return };

            if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
            {
                match load_authorized_keys(&auth_keys_path) {
                    Ok(new_keys) => {
                        *keys_clone.write().unwrap() = new_keys.into();
                    }
                    Err(e) => print_err(&e),
                }
            }
        })?;

    watcher.watch(path, NonRecursive)?;

    // Leaks the watcher, so it stays alive until the daemon exits.
    Box::leak(Box::new(watcher));

    Ok(keys)
}

pub fn load_authorized_keys(
    authorized_keys_path: &Path,
) -> Res<Vec<PublicKey>> {
    Ok(ssh_key::AuthorizedKeys::read_file(authorized_keys_path)?
        .iter()
        .map(|e| e.public_key().clone())
        .collect::<Vec<_>>())
}

pub async fn authenticate_and_accept_connection(
    stream: TcpStream,
    address: SocketAddr,
    context: Arc<Context>,
) -> Res<()> {
    let authorized_keys = context.authorized_keys.read().unwrap().clone();
    let rate_limiter = Arc::clone(&context.rate_limiter);

    let socket = async move {
        let mut socket = timeout(context.acceptor.accept(stream)).await??;

        timeout(authenticate(&mut socket, &authorized_keys))
            .await?
            .inspect_err(|_| {
                log!(e "Signature verification failed for {address}");
            })?;
        Ok::<_, BoxedError>(socket)
    }
    .await
    .inspect_err(|_| rate_limiter.increment(address.ip()))?;

    log!("Authorized connection from {address}");

    let mut socket = handle_client_connection(socket).await?;

    socket.shutdown().await?;
    Ok(())
}

pub async fn authenticate(
    stream: &mut TlsStream<TcpStream>,
    authorized_keys: &[PublicKey],
) -> Res<()> {
    let challenge = rand::random::<[u8; 32]>();
    stream.write_all(&challenge).await?;

    let mut signature_length_reader = [0u8; 4];
    stream.read_exact(&mut signature_length_reader).await?;
    let signature_length = u32::from_be_bytes(signature_length_reader) as usize;

    if signature_length > 4096 {
        return kill_stream(stream, "Signature too large").await;
    }

    let mut signature_bytes = vec![0u8; signature_length];
    stream.read_exact(&mut signature_bytes).await?;

    let signature = match SshSig::from_pem(signature_bytes) {
        Ok(sig) => sig,
        Err(e) => return kill_stream(stream, e).await,
    };

    if !authorized_keys
        .iter()
        .any(|entry| entry.verify("ssh0-auth", &challenge, &signature).is_ok())
    {
        return kill_stream(stream, "Unauthorized").await;
    }

    stream.write_all(&[1]).await?;
    stream.flush().await?;

    Ok(())
}

async fn kill_stream(
    stream: &mut TlsStream<TcpStream>,
    error: impl Into<BoxedError>,
) -> Res<()> {
    stream.write_all(&[0]).await?;
    stream.flush().await?;
    stream.shutdown().await?;

    Err(error.into())
}
