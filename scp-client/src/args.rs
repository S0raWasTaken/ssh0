use argh::{FromArgValue, FromArgs};
use libssh0_client::Res;
use std::path::PathBuf;

/// Copy files to/from a remote host via ssh0
#[derive(FromArgs)]
pub struct Args {
    /// source: either "host:path" or a local path
    #[argh(positional)]
    pub source: ScpTarget,

    /// destination: either "host:path" or a local path
    #[argh(positional)]
    pub destination: ScpTarget,

    /// port (default: 2121)
    #[argh(option, default = "2121")]
    pub port: u16,

    /// private key path
    #[argh(option, short = 'i')]
    pub key_path: Option<PathBuf>,
}

pub enum ScpTarget {
    Local(PathBuf),
    Remote { host: String, path: PathBuf },
}

impl FromArgValue for ScpTarget {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        if let Some((host, path)) = value.split_once(':') {
            Ok(Self::Remote {
                host: host.to_string(),
                path: PathBuf::from(path),
            })
        } else {
            Ok(Self::Local(PathBuf::from(value)))
        }
    }
}

pub fn parse_args() -> Res<Args> {
    let args: Args = argh::from_env();

    match (&args.source, &args.destination) {
        (ScpTarget::Local(_), ScpTarget::Local(_))
        | (ScpTarget::Remote { .. }, ScpTarget::Remote { .. }) => {
            return Err("invalid arguments: \
                    exactly one source and one destination must be remote"
                .into());
        }
        _ => (),
    }

    Ok(args)
}
