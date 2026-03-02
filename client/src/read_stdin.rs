use libssh0::break_if;
use tokio::sync::mpsc::Sender;

#[cfg(not(windows))]
pub fn read_stdin(tx: &Sender<Vec<u8>>) {
    use std::io::{Read, stdin};

    let mut buf = [0u8; 1024];
    loop {
        match stdin().read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                break_if!(tx.blocking_send(buf[..n].to_vec()).is_err());
            }
        }
    }
}

#[cfg(windows)]
pub fn read_stdin(tx: &Sender<Vec<u8>>) {
    loop {
        use crossterm::event::{self, Event, KeyCode, KeyEvent};

        match event::read() {
            Ok(Event::Key(KeyEvent {
                code,
                modifiers,
                kind: KeyEventKind::Press | KeyEventKind::Repeat,
                ..
            })) => {
                let bytes = match code {
                    KeyCode::Char(char) => check_ctrl(modifiers, char),
                    KeyCode::Enter => vec![b'\r'],
                    KeyCode::Backspace => vec![b'\x7f'],
                    KeyCode::Tab => vec![b'\t'],
                    KeyCode::Esc => vec![b'\x1b'],
                    KeyCode::Up => vec![b'\x1b', b'[', b'A'],
                    KeyCode::Down => vec![b'\x1b', b'[', b'B'],
                    KeyCode::Right => vec![b'\x1b', b'[', b'C'],
                    KeyCode::Left => vec![b'\x1b', b'[', b'D'],
                    KeyCode::Home => vec![b'\x1b', b'[', b'H'],
                    KeyCode::End => vec![b'\x1b', b'[', b'F'],
                    KeyCode::Delete => vec![b'\x1b', b'[', b'3', b'~'],
                    KeyCode::PageUp => vec![b'\x1b', b'[', b'5', b'~'],
                    KeyCode::PageDown => vec![b'\x1b', b'[', b'6', b'~'],
                    _ => continue,
                };
                break_if!(tx.blocking_send(bytes).is_err());
            }
            Err(_) => break,
            _ => (),
        }
    }
}

#[cfg(windows)]
use crossterm::event::{KeyEventKind, KeyModifiers};

#[cfg(windows)]
fn check_ctrl(modifiers: KeyModifiers, c: char) -> Vec<u8> {
    if modifiers.contains(KeyModifiers::CONTROL) {
        vec![(c as u8) & 0x1f]
    } else {
        let mut buf = [0u8; 4];
        c.encode_utf8(&mut buf).as_bytes().to_vec()
    }
}
