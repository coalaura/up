#!/usr/bin/env sh
set -e

OS=$(uname -s | tr 'A-Z' 'a-z')
[ "$OS" = linux ] || [ "$OS" = darwin ] || {
	echo "Unsupported OS: $OS" >&2; exit 1;
}

ARCH=$(uname -m)
case "$ARCH" in
	x86_64)
		ARCH=amd64
		;;
	aarch64|arm64)
		ARCH=arm64
		;;
	*)
		echo "Unsupported architecture: $ARCH" >&2
		exit 1
		;;
esac

echo "Resolving latest version..."

VERSION=$(curl -sL https://api.github.com/repos/coalaura/up/releases/latest | grep -Po '"tag_name": *"\K.*?(?=")')

if ! printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "Error: '$VERSION' is not in vMAJOR.MINOR.PATCH format" >&2
	exit 1
fi

rm -f /tmp/up

BIN="up_${VERSION}_${OS}_${ARCH}"
URL="https://github.com/coalaura/up/releases/download/${VERSION}/${BIN}"

echo "Downloading ${BIN}..."

if ! curl -sL "$URL" -o /tmp/up; then
	echo "Error: failed to download $URL" >&2
	exit 1
fi

trap 'rm -f /tmp/up' EXIT

chmod +x /tmp/up

echo "Installing to /usr/local/bin/up requires sudo"

if ! sudo install -m755 /tmp/up /usr/local/bin/up; then
	echo "Error: install failed" >&2
	exit 1
fi

echo "up $VERSION installed to /usr/local/bin/up"