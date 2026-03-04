use super::Res;
use crate::{BoxedError, context::Context, fingerprint, scp, ssh};
use libssh0::{
    common::{CHALLENGE_SIZE, SessionType, handshake},
    log, read, read_exact, timeout,
};
use ssh_key::{PublicKey, SshSig};
use std::{net::SocketAddr, sync::Arc};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::server::TlsStream;

pub async fn authenticate_and_accept_connection(
    stream: TcpStream,
    address: SocketAddr,
    context: Arc<Context>,
) -> Res<()> {
    let authorized_keys = context.authorized_keys.read().unwrap().clone();
    let rate_limiter = Arc::clone(&context.rate_limiter);

    let ctx = Arc::clone(&context);
    let (socket, (public_key, session_type)) = async move {
        let mut socket = timeout(ctx.acceptor.accept(stream)).await??;

        let public_key = timeout(authenticate(&mut socket, &authorized_keys))
            .await?
            .inspect_err(|_| {
                log!(e "Signature verification failed for {address}");
            })?;
        Ok::<_, BoxedError>((socket, public_key))
    }
    .await
    .inspect_err(|_| rate_limiter.increment(address.ip()))?;

    log!("Authorized connection from {address}");
    context.rate_limiter.reset(address.ip());

    let (session, _session_guard) = context.register_session(
        fingerprint(&public_key),
        address,
        session_type,
    )?;

    let mut socket = match session_type {
        SessionType::Shell => {
            ssh::handle_client_connection(socket, session).await?
        }
        SessionType::Upload => scp::handle_upload(socket).await?,
        SessionType::Download => scp::handle_download(socket).await?,
    };

    socket.shutdown().await?;
    Ok(())
}

pub async fn authenticate(
    mut stream: &mut TlsStream<TcpStream>,
    authorized_keys: &[PublicKey],
) -> Res<(PublicKey, SessionType)> {
    let session_type = handshake(stream).await?;

    let challenge = rand::random::<[u8; CHALLENGE_SIZE]>();
    stream.write_all(&challenge).await?;

    let signature_length =
        u32::from_be_bytes(read_exact!(stream, 4).await?) as usize;

    if signature_length > 4096 {
        kill_stream(stream, "Signature too large").await?;
    }

    let signature_bytes = read!(stream, signature_length).await?;

    let signature = match SshSig::from_pem(signature_bytes) {
        Ok(sig) => sig,
        Err(e) => kill_stream(stream, e).await?,
    };

    let matched_key = match authorized_keys
        .iter()
        .find(|e| e.verify("ssh0-auth", &challenge, &signature).is_ok())
    {
        Some(key) => key.clone(),
        None => kill_stream(stream, "Unauthorized").await?,
    };

    stream.write_all(&[1]).await?;
    stream.flush().await?;

    Ok((matched_key, session_type))
}

// mut stream &mut is painful, but the macro requires it
async fn handshake(mut stream: &mut TlsStream<TcpStream>) -> Res<SessionType> {
    stream.write_all(&handshake::KEYGEN).await?;
    let response = read_exact!(stream, 6).await?;

    if response != handshake::CHURCH {
        kill_stream(stream, "Invalid handshake").await?;
    }

    stream.write_all(&handshake::PRAISE_THE_CODE).await?;

    let Some(session_type) =
        SessionType::from_byte(read_exact!(stream, 1).await?)
    else {
        kill_stream(stream, "Invalid session type").await?;
    };

    Ok(session_type)
}

async fn kill_stream(
    stream: &mut TlsStream<TcpStream>,
    error: impl Into<BoxedError>,
) -> Res<!> {
    stream.write_all(&[0]).await?;
    stream.flush().await?;
    stream.shutdown().await?;

    Err(error.into())
}
