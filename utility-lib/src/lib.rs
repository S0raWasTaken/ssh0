pub mod common;
mod dropguard;
mod password;

use std::error::Error;

pub use chrono;
pub use dropguard::DropGuard;
pub use password::{prompt_passphrase, prompt_passphrase_twice};

pub type BoxedError = Box<dyn Error + Send + Sync>;
pub type Res<T> = Result<T, BoxedError>;

#[cfg(feature = "tokio")]
pub use tokio;

/// Wraps a future with a 10-second timeout.
///
/// # Errors
/// Returns [`tokio::time::error::Elapsed`] if the future does not complete within 10 seconds.
#[cfg(feature = "tokio")]
pub async fn timeout<F: IntoFuture>(
    f: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(std::time::Duration::from_secs(10), f).await
}

/// Logs a timestamped message to stdout or stderr.
///
/// # Usage
/// ```
/// log!("Connected from {address}");       // stdout
/// log!(e "Auth failed for {address}");    // stderr
/// ```
#[macro_export]
macro_rules! log {
    (e $($arg:tt)*) => {
        eprintln!("[{}] {}", $crate::chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), format_args!($($arg)*))
    };
    ($($arg:tt)*) => {
        println!("[{}] {}", $crate::chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), format_args!($($arg)*))
    };
}

/// Breaks out of the current loop if the given expression is `true`.
///
/// # Example
/// ```
/// break_if!(n == 0 || tx.send(data).await.is_err());
/// ```
#[macro_export]
macro_rules! break_if {
    ($x:expr) => {
        if $x {
            break;
        }
    };
}

/// Reads an exact number of bytes from an async stream into a `Vec<u8>`.
///
/// # Usage
/// ```
/// let signature = read!(stream, signature_length).await?;
/// ```
#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! read {
    ($stream:expr, $len:expr) => {{
        async {
            let mut buf = vec![0u8; $len];
            $crate::tokio::io::AsyncReadExt::read_exact(&mut $stream, &mut buf)
                .await?;
            Ok::<_, std::io::Error>(buf)
        }
    }};
}

/// Reads an exact number of bytes from an async stream into a fixed-size array.
/// Length must be a const.
///
/// # Usage
/// ```
/// let greeting = read_exact!(stream, 6).await?;
/// ```
#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! read_exact {
    ($stream:expr, $len:expr) => {{
        async {
            let mut buf = [0u8; $len];
            $crate::tokio::io::AsyncReadExt::read_exact(&mut $stream, &mut buf)
                .await?;
            Ok::<_, std::io::Error>(buf)
        }
    }};
}
