
UP is a simple file transfer tool that acts as a drop-in replacement for `scp` and `sftp`. It sends data over HTTPS for much faster uploads without any extra setup. Up uses your existing SSH keys and reads `~/.ssh/config` so you can keep working with the host aliases you already have.

## Why UP?

- Transfers are noticeably quicker than traditional `scp` or `sftp`.
- No setup: use the same SSH keys and host aliases you already have.
- Small single binary for sending and receiving.

## Installation

You can bootstrap **up** with a single command.
This script will detect your OS (`linux`/`darwin`) and CPU (`amd64`/`arm64`),
download the correct binary and install it to `/usr/local/bin/up`.

```bash
curl -sL https://raw.githubusercontent.com/coalaura/up/master/install.sh | sh
```

## Quick Start

Pre-built binaries for common operating systems are available in the [releases](https://github.com/coalaura/up/releases/latest). Choose the download that matches your OS and architecture or build the latest development version yourself:

```bash
go build -o up .
```

Start the server (listens on port 7966) and then upload a file:

```bash
./up receive

./up send very_big.tar.xz localhost:7966
```

Uploaded files are stored under the server's `files/` directory. Up will prompt to trust the server's certificate on first use and will remember it afterwards. Up is built to work behind reverse proxies like nginx.

## License

This project is licensed under the GNU General Public License v3.0 License. See [LICENSE](LICENSE) for details.