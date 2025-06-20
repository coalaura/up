
UP is a simple file transfer tool that acts as a drop-in replacement for `scp` and `sftp`. It sends data over HTTPS for much faster uploads without any extra setup. Up uses your existing SSH keys and reads `~/.ssh/config` so you can keep working with the host aliases you already have.

## Why UP?

- Transfers are noticeably quicker than traditional `scp` or `sftp`.
- No setup: use the same SSH keys and host aliases you already have.
- Small single binary for sending and receiving.
- Uses TLS 1.3 with HTTP/2 by default and supports HTTP/3 with `--http3`/`-h3`.

| | Protocol | Performance Considerations |
| :- | :- | :- |
| `scp` | SSH (TCP) | Typically uses a single TCP connection, limited by TCP window size and RTT. Can incur higher per-byte overhead from SSH protocol framing and encryption for raw data. |
| `sftp` | SSH (TCP) | Similar to `scp` in TCP limitations, though the SFTP protocol itself can be slightly more efficient for block-based transfers. Still subject to SSH overhead. |
| `https` | TLS over HTTP (TCP/QUIC) | Benefits from modern TCP stack optimizations. HTTP/2 and HTTP/3 (QUIC) allow for efficient multiplexing and reduced latency. Optimized for large data streams. |

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

Uploaded files are stored under the server's `files/` directory. Up will prompt to trust the server's certificate on first use and will remember it afterwards. The server forces HTTP/2 with TLS 1.3 by default. Pass `--http3` or `-h3` on both the server and client to switch to HTTP/3 over QUIC. When HTTP/3 mode is enabled, Up will not work behind reverse proxies like nginx.

## Reverse Proxy Setup (http2)

Here is an example nginx configuration that proxies HTTPS traffic to an Up server running locally. Replace the certificate paths with your own.

```nginx
server {
    listen 443 ssl;
    server_name up.example.com;

    ssl_certificate /etc/ssl/certs/example.pem;
    ssl_certificate_key /etc/ssl/private/example.key;

    location / {
        proxy_pass https://127.0.0.1:7966;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_ssl_verify off;
    }
}
```

## License

This project is licensed under the GNU General Public License v3.0 License. See [LICENSE](LICENSE) for details.