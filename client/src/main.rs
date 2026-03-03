use crate::{
    args::Args, fingerprint::FingerprintCheck, read_stdin::read_stdin,
};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dirs::config_dir;
use libssh0::{DropGuard, break_if, prompt_passphrase, read_exact, timeout};
use ssh_key::{LineEnding, PrivateKey};
use std::{
    error::Error,
    io::{ErrorKind::UnexpectedEof, Write, stdout},
    path::PathBuf,
    process::exit,
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    net::TcpStream,
    spawn,
    sync::mpsc::{Receiver, channel},
    task::spawn_blocking,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{ClientConfig, pki_types::ServerName},
};

type BoxedError = Box<dyn Error + Send + Sync>;
type Res<T> = Result<T, BoxedError>;

mod args;
mod fingerprint;
mod read_stdin;

#[tokio::main]
async fn main() -> Res<()> {
    let Args { host, port, key_path } = argh::from_env();

    let private_key = load_private_key(key_path)?;

    enable_raw_mode()?;
    let guard = DropGuard::new((), |()| {
        disable_raw_mode().ok();
    });

    let mut stream = connect_tls(&host, port).await?;

    timeout(authenticate(&mut stream, private_key)).await??;

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

async fn connect_tls(host: &str, port: u16) -> Res<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintCheck))
            .with_no_client_auth(),
    ));

    let tcp = timeout(TcpStream::connect((host, port))).await??;

    let domain = ServerName::try_from(host.to_string())?;

    Ok(timeout(connector.connect(domain, tcp)).await??)
}

const POSSIBLE_PATHS: [&str; 2] = ["id_ed25519", "id_rsa"];
fn load_private_key(key_path: Option<PathBuf>) -> Res<PrivateKey> {
    let private_key_path = key_path.map_or_else(|| {
        let config_dir =
            config_dir().ok_or("Config dir not found")?.join("ssh0");
        let key_path = POSSIBLE_PATHS.iter().find(|entry| {
            config_dir.join(entry).exists()
        }).ok_or("No private keys found in the config directory. Try generating a new key pair using `ssh0-keygen`")?;
        Ok(config_dir.join(key_path))
    }, Ok::<_, BoxedError>)?;

    #[cfg(unix)]
    {
        use std::{fs, os::unix::fs::PermissionsExt};

        let mode = fs::metadata(&private_key_path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "Private key {} has too permissive permissions ({:o}), expected at most (600)",
                private_key_path.display(),
                mode & 0o777
            ).into());
        }
    }

    let mut private_key = PrivateKey::read_openssh_file(&private_key_path)?;

    if private_key.is_encrypted() {
        let passphrase = prompt_passphrase("Enter passphrase: ")?;
        private_key = private_key
            .decrypt(passphrase)
            .map_err(|e| format!("Incorrect password ({e})"))?;
    }

    Ok(private_key)
}

async fn authenticate(
    mut stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    private_key: PrivateKey,
) -> Res<()> {
    handshake(stream).await?;

    let challenge = read_exact!(stream, 32).await?;

    let signature = private_key
        .sign("ssh0-auth", ssh_key::HashAlg::Sha512, &challenge)?
        .to_pem(LineEnding::default())?;
    let signature_bytes = signature.as_bytes();

    #[expect(clippy::cast_possible_truncation)]
    stream.write_all(&(signature_bytes.len() as u32).to_be_bytes()).await?;
    stream.write_all(signature_bytes).await?;

    let result = read_exact!(stream, 1).await?;
    if result[0] != 1 {
        return Err("Authentication failed".into());
    }

    Ok(())
}

async fn handshake(
    mut stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Res<()> {
    let keygen = read_exact!(stream, 6).await?;
    if &keygen != b"Keygen" {
        return Err("Invalid Handshake".into());
    }

    stream.write_all(b"Church").await?;
    let response = read_exact!(stream, 16).await?;

    if &response != b"PRAISE THE CODE!" {
        return Err("Invalid Handshake".into());
    }

    println!("\x1b[1;31m░█░█░░█░█░█░ PRAISE THE CODE! ░█░█░░█░█░█░\x1b[0m");
    Ok(())
}

async fn forward_to_server<S: AsyncWrite>(
    mut rx: Receiver<Vec<u8>>,
    mut tcp_tx: WriteHalf<S>,
) {
    while let Some(data) = rx.recv().await {
        break_if!(tcp_tx.write_all(&data).await.is_err());
    }
}
