# UP

UP is a simple file transfer tool that acts as a drop-in replacement for `scp` and `sftp`. It sends data over HTTPS for much faster uploads without any extra setup. The client uses your existing SSH keys and reads `~/.ssh/config` so you can keep working with the host aliases you already have.

## Why UP?

- Transfers are noticeably quicker than traditional `scp` or `sftp`.
- No setup: use the same SSH keys and host aliases you already have.
- Small client and server binaries.

## Quick Start

Pre-built binaries for common operating systems are available on the releases page. Choose the download that matches your OS and architecture or build the latest development version yourself:

```bash
go build -o server ./server
go build -o up ./client
```

Start the server (listens on port 7966) and then upload a file:

```bash
./server

./up very_big.tar.xz localhost:7966
```

Uploaded files are stored under the server's `files/` directory. The client will prompt to trust the server's certificate on first use and will remember it afterwards. Up is built to work behind reverse proxies like nginx.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
