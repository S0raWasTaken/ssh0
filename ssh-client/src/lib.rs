use dirs::config_dir;
use libssh0::{
    BoxedError, Res,
    common::{CHALLENGE_SIZE, SessionType, handshake::handshake_client},
    prompt_passphrase, read_exact, timeout,
};
use ssh_key::{LineEnding, PrivateKey};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{ClientConfig, pki_types::ServerName},
};

use crate::fingerprint::FingerprintCheck;
use std::path::PathBuf;
use std::sync::Arc;

mod fingerprint;

/// Establishes a TLS connection to the given host and port, verifying the
/// server's certificate fingerprint via TOFU.
///
/// # Errors
/// Returns an error if the TCP connection fails, the TLS handshake fails,
/// or the user rejects the server's fingerprint.
pub async fn connect_tls(host: &str, port: u16) -> Res<TlsStream<TcpStream>> {
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

/// Loads a private key from the given path, or searches the default config
/// directory for `id_ed25519` or `id_rsa` if no path is provided.
///
/// On Unix, verifies that the key file has permissions of at most `0o600`.
/// If the key is encrypted, prompts the user for a passphrase interactively.
///
/// # Errors
/// Returns an error if no key is found, permissions are too permissive,
/// the file cannot be read, or the passphrase is incorrect.
pub fn load_private_key(key_path: Option<PathBuf>) -> Res<PrivateKey> {
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
        if mode & 0o177 != 0 {
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

/// Performs the protocol handshake and keypair authentication with the server.
///
/// Sends a session type during the handshake, signs the server's
/// 256-byte challenge with the private key using `SshSig`/SHA-512, and
/// verifies the server's response.
///
/// # Errors
/// Returns an error if the handshake fails, the signature cannot be
/// computed, or the server rejects the authentication.
pub async fn authenticate(
    mut stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    private_key: &PrivateKey,
    session_type: SessionType,
    print_banner: bool,
) -> Res<()> {
    handshake_client(stream, session_type, print_banner).await?;

    let challenge = read_exact!(stream, CHALLENGE_SIZE).await?;

    let signature = private_key
        .sign("ssh0-auth", ssh_key::HashAlg::Sha512, &challenge)?
        .to_pem(LineEnding::default())?;
    let signature_bytes = signature.as_bytes();

    stream
        .write_all(&u32::try_from(signature_bytes.len())?.to_be_bytes())
        .await?;
    stream.write_all(signature_bytes).await?;

    let result = read_exact!(stream, 1).await?;
    if result[0] != 1 {
        return Err("Authentication failed".into());
    }

    Ok(())
}
