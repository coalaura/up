#!/usr/bin/env sh
set -e

OS=$(uname -s | tr 'A-Z' 'a-z')
[ "$OS" = linux ] || [ "$OS" = darwin ] || {
	echo "Unsupported OS: $OS" >&2; exit 1;
}

# 2) Arch detection
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

VERSION=$(curl -sL https://api.github.com/repos/coalaura/up/releases/latest | grep -Po '"tag_name": *"\K.*?(?=")')

if ! printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "Error: '$VERSION' is not in vMAJOR.MINOR.PATCH format" >&2
	exit 1
fi

curl -sL "https://github.com/coalaura/up/releases/download/${VERSION}/up_${VERSION}_${OS}_${ARCH}" -o up \
  && chmod +x up \
  && install -m755 up /usr/local/bin/up \
  && rm up

echo "up ${VERSION} installed to /usr/local/bin/up"