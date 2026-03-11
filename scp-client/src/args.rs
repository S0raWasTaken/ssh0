use argh::{FromArgValue, FromArgs};
use libssh0::{Res, common::SessionType};
use std::{
    io::{
        self,
        ErrorKind::{InvalidData, InvalidFilename, IsADirectory, NotFound},
    },
    path::{Path, PathBuf},
};

/// Copy files to/from a remote host via ssh0
#[derive(FromArgs)]
struct CommandArgs {
    #[argh(positional)]
    pub files: Vec<ScpTarget>,

    /// port (default: 2121)
    #[argh(option, default = "2121")]
    pub port: u16,

    /// private key path
    #[argh(option, short = 'i')]
    pub key_path: Option<PathBuf>,

    /// number of transfers at once (default: 15)
    #[argh(option, short = 'u', default = "15")]
    pub task_limit: usize,
}

#[derive(Clone)]
pub enum ScpTarget {
    Local(PathBuf),
    Remote { host: String, path: PathBuf, glob: bool },
}

impl FromArgValue for ScpTarget {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        if let Some((host, path)) = value.rsplit_once(':') {
            Ok(Self::Remote {
                host: host.to_string(),
                path: PathBuf::from(path),
                glob: path.contains('*'),
            })
        } else {
            Ok(Self::Local(PathBuf::from(value)))
        }
    }
}

#[derive(Debug)]
pub struct FileInfo {
    pub path: PathBuf,
    pub name: String,
}

impl FileInfo {
    pub fn new(path: PathBuf, name: String) -> Self {
        Self { path, name }
    }
}

pub struct UnparsedGlob {
    pub path: PathBuf,
    pub host: String,
}

impl From<ScpTarget> for UnparsedGlob {
    fn from(value: ScpTarget) -> Self {
        match value {
            ScpTarget::Local(_) => panic!("This shouldn't happen"),
            ScpTarget::Remote { host, path, glob: true } => Self { path, host },
            ScpTarget::Remote { glob: false, .. } => {
                panic!("This shouldn't happen either")
            }
        }
    }
}

pub struct Args {
    pub session_type: SessionType,
    pub source_files: Vec<FileInfo>,
    pub unparsed_globs: Vec<UnparsedGlob>,
    pub destination: PathBuf,
    pub key_path: Option<PathBuf>,
    pub host: String,
    pub port: u16,
    pub task_limit: usize,
}

const INVALID: &str = "Invalid";

const MIXED_ARGS_ERROR: &str = "\
Mixed arguments found, can't determine what to do. \
(Source files must not contain both local and host entries).

This is supported:
    scp0 host:path1 host:path2 host:path3 ~/local_path
    scp0 ~/local_path1 ~/local_path2 ~/local_path3 host:path

This makes no sense:
    scp0 host:path1 ~/local_path1 host:path2";

const EASTER_EGG: &str = "\
Nice try. The program would quit instantly anyway :)";

const INVALID_ARGS: &str = "\
Invalid arguments: exactly one source and one dcestination must be remote";

const GLOB_ON_DESTINATION: &str = "Glob not supported on destination";

impl Args {
    pub fn from_argh() -> Res<Self> {
        let args: CommandArgs = argh::from_env();
        if args.task_limit == 0 {
            eprintln!("{EASTER_EGG}");
            return Err(INVALID.into());
        }

        let len = args.files.len();

        if len < 2 {
            eprintln!("{INVALID_ARGS}");
            return Err(INVALID.into());
        }

        let source_files = &args.files[..len - 1];
        let destination = &args.files[len - 1];

        let (globs, source_files): (Vec<_>, Vec<_>) =
            source_files.iter().partition(|target| {
                matches!(target, ScpTarget::Remote { glob: true, .. })
            });

        let unparsed_globs: Vec<UnparsedGlob> =
            globs.into_iter().cloned().map(UnparsedGlob::from).collect();

        if matches!(destination, ScpTarget::Remote { glob: true, .. }) {
            eprintln!("{GLOB_ON_DESTINATION}");
            return Err(INVALID.into());
        }

        if args_are_mixed(&source_files, destination) {
            eprintln!("{MIXED_ARGS_ERROR}");
            return Err(INVALID.into());
        }

        let session_type = match destination {
            ScpTarget::Local(_) => SessionType::Download,
            ScpTarget::Remote { .. } => SessionType::Upload,
        };

        let (host, source_files, destination) = match session_type {
            SessionType::Upload => {
                let ScpTarget::Remote { host, path, .. } = destination else {
                    unreachable!()
                };
                let sources = source_files
                    .iter()
                    .map(|f| match f {
                        ScpTarget::Local(p) => validate_local_source(p.clone()),
                        ScpTarget::Remote { .. } => unreachable!(),
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                (host.clone(), sources, expand_tilde(path.clone())?)
            }
            SessionType::Download => {
                let host = source_files
                    .iter()
                    .find_map(|f| match f {
                        ScpTarget::Remote { host, .. } => Some(host.clone()),
                        ScpTarget::Local(_) => None,
                    })
                    .or_else(|| {
                        unparsed_globs.iter().map(|f| f.host.clone()).next()
                    })
                    .ok_or("No remote source found")?;
                let sources = source_files
                    .iter()
                    .map(|f| match f {
                        ScpTarget::Remote { path, .. } => {
                            let name = extract_remote_filename(path)?;
                            Ok(FileInfo::new(path.clone(), name))
                        }
                        ScpTarget::Local(_) => unreachable!(),
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                let ScpTarget::Local(dest) = destination else {
                    unreachable!()
                };
                (host, sources, expand_tilde(dest.clone())?)
            }
            SessionType::Shell | SessionType::Probe => unreachable!(),
        };

        Ok(Self {
            session_type,
            source_files,
            destination,
            host,
            key_path: args.key_path,
            port: args.port,
            unparsed_globs,
            task_limit: args.task_limit,
        })
    }
}

// Prevents `scp0 host:~/file1 local_file1 host:~/destination_dir` (or vice versa)
fn args_are_mixed(
    source_files: &[&ScpTarget],
    destination: &ScpTarget,
) -> bool {
    let destination_is_local = matches!(destination, ScpTarget::Local(_));
    source_files
        .iter()
        .any(|file| matches!(file, ScpTarget::Local(_)) == destination_is_local)
}

fn expand_tilde(path: PathBuf) -> io::Result<PathBuf> {
    if let Ok(stripped) = path.strip_prefix("~") {
        let home = dirs::home_dir().ok_or_else(|| {
            io::Error::new(NotFound, "Could not find home directory")
        })?;
        Ok(home.join(stripped))
    } else {
        Ok(path)
    }
}

pub fn validate_local_source(path: PathBuf) -> io::Result<FileInfo> {
    let path = expand_tilde(path)?;

    if !path.try_exists()? {
        return Err(io::Error::new(NotFound, "Local file not found"));
    }

    if path.is_dir() {
        return Err(io::Error::new(
            IsADirectory,
            "Local entity is a directory",
        ));
    }

    let file_name = path
        .file_name()
        .ok_or(InvalidFilename)?
        .to_os_string()
        .into_string()
        .map_err(|_| {
            io::Error::new(InvalidData, "File name is not valid UTF-8")
        })?;

    Ok(FileInfo::new(path, file_name))
}

pub fn extract_remote_filename(path: &Path) -> io::Result<String> {
    path.file_name()
        .ok_or(InvalidFilename)?
        .to_os_string()
        .into_string()
        .map_err(|_| {
            io::Error::new(InvalidData, "File name is not valid UTF-8")
        })
}
