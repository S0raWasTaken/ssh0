# ssh0

A custom SSH-like protocol in Rust. TLS transport, keypair auth, PTY-backed remote shell.

> **Note:** The daemon is designed to run as a non-privileged user account.
> It does not perform path restriction or chroot isolation; authenticated
> clients have the same filesystem access as the user running the daemon.
> **Do not run the daemon as root.**

> By the way, this is a personal project. It technically features a stricter
> security standard than OpenSSH, but it lacks the years and years of pentesting
> that OpenSSH did get, so I wouldn't trust this on something that requires
> a ton of security. I wouldn't trust just OpenSSH to do the job! 

> At least run this (or even OpenSSH) under a virtual private network, like Tailscale. Your log files will thank you :)

## Setup

**1. Generate a key pair**
```bash
ssh0-keygen
```
Saves to `~/.config/ssh0/` by default.

**2. Authorize your public key on the server**

**3. Start the daemon**
```bash
ssh0-daemon              # binds to 127.0.0.1:2121
ssh0-daemon 0.0.0.0      # all interfaces
```
TLS cert is auto-generated on first run.

**4. Connect**
```bash
ssh0 hostname
ssh0 hostname --port 2222
ssh0 hostname -i /path/to/key

# or, try out SCP
scp0 hostname:~/path/to/file .
scp0 ./file.txt hostname:~
# it also supports --port and -i arguments
```
On first connection you'll be asked to verify the server's TLS fingerprint.

## Known Limitations

- No terminal resize support (next update)
- No port forwarding
