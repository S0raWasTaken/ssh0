use argh::{FromArgValue, FromArgs};
use ssh_key::Algorithm;
use std::path::PathBuf;

impl From<KeypairType> for Algorithm {
    fn from(val: KeypairType) -> Self {
        match val {
            KeypairType::Ed25519 => Self::Ed25519,
            KeypairType::Rsa512 => {
                Self::Rsa { hash: Some(ssh_key::HashAlg::Sha512) }
            }
            KeypairType::Rsa256 => {
                Self::Rsa { hash: Some(ssh_key::HashAlg::Sha256) }
            }
        }
    }
}

#[derive(Default, Debug)]
pub enum KeypairType {
    #[default]
    Ed25519,
    Rsa512,
    Rsa256,
}

impl FromArgValue for KeypairType {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        match &*value.to_lowercase() {
            "ed" | "ed25519" => Ok(KeypairType::Ed25519),
            "rsa" | "rsa512" => Ok(KeypairType::Rsa512),
            "rsa256" => Ok(KeypairType::Rsa256),
            _ => Err(format!(
                "Invalid key pair type '{value}'. \
                Accepted values: rsa, rsa256, rsa512, ed, ed25519"
            )),
        }
    }
}

/// Generates a new authentication key for ssh0.
#[derive(FromArgs, Debug)]
pub struct Args {
    /// accepted values: rsa, rsa256, rsa512, ed, ed25519
    #[argh(option, short = 't', default = "KeypairType::default()")]
    pub r#type: KeypairType,

    /// output path; if omitted, defaults to OS-specific config dir
    #[argh(option, short = 'o')]
    pub output: Option<PathBuf>,

    /// a passphrase for your generated private key.
    #[argh(option, short = 'N')] // yup, same as openssh
    pub passphrase: Option<String>,
}
