use std::{
    io::{self, ErrorKind::Interrupted, Write, stdout},
    ops::ControlFlow,
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};

use crate::DropGuard;

/// Prompts the user for a passphrase, displaying `*` for each character typed.
/// Supports backspace to correct mistakes.
///
/// # Example
/// ```
/// let passphrase = prompt_passphrase("Enter passphrase: ")?;
/// ```
///
/// # Errors
/// Returns an error if reading terminal input fails or if raw mode cannot be enabled.
pub fn prompt_passphrase(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    stdout().flush()?;

    enable_raw_mode()?;
    let _guard = DropGuard::new((), |()| {
        disable_raw_mode().ok();
        println!();
    });
    let mut passphrase = String::new();

    loop {
        if let ControlFlow::Break(()) =
            event_parser(&event::read()?, &mut passphrase)?
        {
            break;
        }
    }
    Ok(passphrase)
}

/// Prompts the user for a passphrase twice and verifies they match.
///
/// If the first passphrase is empty, the confirmation prompt is skipped.
///
/// # Errors
/// Returns an error if the passphrases don't match, if reading terminal
/// input fails, or if raw mode cannot be enabled.
pub fn prompt_passphrase_twice(
    prompt1: &str,
    prompt2: &str,
) -> io::Result<String> {
    let pf1 = prompt_passphrase(prompt1)?;

    if pf1.is_empty() {
        return Ok(pf1);
    }

    let pf2 = prompt_passphrase(prompt2)?;
    if pf1 != pf2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Passphrases don't match",
        ));
    }
    Ok(pf1)
}

fn event_parser(
    event: &Event,
    passphrase: &mut String,
) -> io::Result<ControlFlow<()>> {
    if let Event::Key(KeyEvent {
        code,
        kind: KeyEventKind::Press | KeyEventKind::Repeat,
        modifiers,
        ..
    }) = event
    {
        return match code {
            KeyCode::Enter => Ok(ControlFlow::Break(())),
            KeyCode::Backspace => {
                if passphrase.pop().is_some() {
                    print_flush("\x08 \x08")?;
                }
                Ok(ControlFlow::Continue(()))
            }
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                return Err(io::Error::new(Interrupted, "Ctrl-C called"));
            }
            KeyCode::Char(c) => {
                passphrase.push(*c);
                print_flush("*")?;
                Ok(ControlFlow::Continue(()))
            }
            _ => Ok(ControlFlow::Continue(())),
        };
    }
    Ok(ControlFlow::Continue(()))
}

fn print_flush(s: &str) -> io::Result<()> {
    print!("{s}");
    stdout().flush()
}
