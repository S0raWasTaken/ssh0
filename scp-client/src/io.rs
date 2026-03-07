use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use libssh0::{DropGuard, common::SCP_BUFFER_SIZE};
use std::{
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::Handle,
};

use crate::Stream;

pub async fn send_file(
    stream: &mut Stream,
    path: &Path,
    multi_progress_bar: MultiProgress,
) -> io::Result<()> {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");

    let mut file = File::open(path).await?;
    let file_size = file.metadata().await?.len();

    stream.write_all(&file_size.to_be_bytes()).await?;
    stream.flush().await?;

    let pb = make_progress_bar(file_size, file_name, &multi_progress_bar);

    let mut remaining = file_size;
    let mut buffer = [0u8; SCP_BUFFER_SIZE];
    while remaining > 0 {
        #[expect(clippy::cast_possible_truncation)]
        let to_read = remaining.min(SCP_BUFFER_SIZE as u64) as usize;
        let n = file.read(&mut buffer[..to_read]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Source file changed during upload",
            ));
        }
        stream.write_all(&buffer[..n]).await?;
        pb.inc(n as u64);
        remaining -= n as u64;
    }

    stream.flush().await?;
    pb.finish_with_message(format!("{file_name} uploaded"));
    Ok(())
}

// We pass file_name and output_path because output_path may be a directory.
// In that scenario, we append file_name to output_path.
pub async fn receive_file(
    stream: &mut Stream,
    output_path: &Path,
    file_name: &str,
    file_size: u64,
    multi_progress_bar: MultiProgress,
) -> io::Result<()> {
    let output_path =
        if tokio::fs::metadata(output_path).await.is_ok_and(|m| m.is_dir()) {
            output_path.join(file_name)
        } else {
            output_path.to_path_buf()
        };

    let temp_path = {
        let mut s = output_path.as_os_str().to_owned();
        s.push(".part");
        PathBuf::from(s)
    };

    let success = AtomicBool::new(false);
    let handle = Handle::current();
    let _part_guard = DropGuard::new((), |()| {
        if !success.load(Relaxed) {
            let temp_path_copy = temp_path.clone();

            handle.spawn(tokio::fs::remove_file(temp_path_copy));
        }
    });

    let mut file = File::create(&temp_path).await?;
    let mut remaining = file_size;
    let mut buffer = [0u8; SCP_BUFFER_SIZE];

    let pb = make_progress_bar(file_size, file_name, &multi_progress_bar);

    while remaining > 0 {
        #[expect(clippy::cast_possible_truncation)]
        let to_read = remaining.min(SCP_BUFFER_SIZE as u64) as usize;
        let n = stream.read(&mut buffer[..to_read]).await?;
        if n == 0 {
            pb.abandon();
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection was aborted prematurely",
            ));
        }
        file.write_all(&buffer[..n]).await?;
        remaining -= n as u64;
        pb.inc(n as u64);
    }
    file.sync_all().await?;

    drop(file);
    tokio::fs::rename(&temp_path, output_path).await?;

    success.store(true, Relaxed);

    pb.finish_with_message(format!("{file_name} downloaded"));
    Ok(())
}

const TEMPLATE: &str = "[{elapsed_precise}] [{bar:40.red.bold/red.bold}] {bytes}/{total_bytes} ({eta}) {msg}";
fn make_progress_bar(
    file_size: u64,
    file_name: &str,
    multi_progress_bar: &MultiProgress,
) -> ProgressBar {
    let pb = multi_progress_bar.add(ProgressBar::new(file_size));
    pb.set_style(
        ProgressStyle::default_bar()
            .template(TEMPLATE)
            .unwrap()
            .progress_chars("██░"),
    );
    pb.set_message(file_name.to_string());
    pb
}
