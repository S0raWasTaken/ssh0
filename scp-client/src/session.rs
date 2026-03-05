use std::{
    io::{
        self,
        ErrorKind::{InvalidData, InvalidFilename, IsADirectory, NotFound},
    },
    path::PathBuf,
};

use libssh0::common::SessionType;

use crate::args::ScpTarget;

#[expect(
    clippy::struct_field_names,
    reason = "I'm deconstructing it immediately."
)]
pub struct Session {
    pub session_type: SessionType,
    pub host: String,
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    pub file_name: String,
}

pub fn define_session_type(
    source: ScpTarget,
    destination: ScpTarget,
) -> io::Result<Session> {
    let session = match (source, destination) {
        (
            ScpTarget::Local(local_file),
            ScpTarget::Remote { host, path: remote_output },
        ) => {
            let local_file = dbg!(expand_tilde(local_file)?);

            if !local_file.try_exists()? {
                return Err(io::Error::new(NotFound, "Local file not found"));
            }

            if local_file.is_dir() {
                return Err(io::Error::new(
                    IsADirectory,
                    "Local entity is a directory",
                ));
            }

            let file_name = local_file
                .file_name()
                .ok_or(InvalidFilename)?
                .to_os_string()
                .into_string()
                .map_err(|_| {
                    io::Error::new(InvalidData, "File name is not valid UTF-8")
                })?;
            Session {
                session_type: SessionType::Upload,
                host,
                source_path: local_file,
                destination_path: remote_output,
                file_name,
            }
        }
        (
            ScpTarget::Remote { host, path: remote_file },
            ScpTarget::Local(local_output),
        ) => {
            let local_output = dbg!(expand_tilde(local_output)?);
            let file_name = remote_file
                .file_name()
                .ok_or(InvalidFilename)?
                .to_os_string()
                .into_string()
                .map_err(|_| {
                    io::Error::new(InvalidData, "File name is not valid UTF-8")
                })?;

            Session {
                session_type: SessionType::Download,
                host,
                source_path: remote_file,
                destination_path: local_output,
                file_name,
            }
        }
        _ => unreachable!(),
    };
    Ok(session)
}

fn expand_tilde(path: PathBuf) -> io::Result<PathBuf> {
    if let Ok(stripped) = path.strip_prefix("~") {
        let home = dirs::home_dir().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Could not find home directory",
            )
        })?;
        Ok(home.join(stripped))
    } else {
        Ok(path)
    }
}
