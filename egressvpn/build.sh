#!/usr/bin/env bash
# Cross-compile for Ubuntu and pack a self-contained tarball.
#
# CGO is off: the binary would otherwise be linked against macOS libc and refuse
# to run on the server. With it off and no external Go modules, the output is a
# static ELF that needs no glibc version match on the target.
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-$(date -u +%Y%m%dT%H%M%SZ)}"
LDFLAGS="-s -w -X main.version=${VERSION}"
BIN=egressvpn
STAGE=dist/${BIN}-${VERSION}

go build ./...
go test ./...

rm -rf "$STAGE"
mkdir -p "$STAGE"
cp example/egress.yaml README.md TUTORIAL.md "$STAGE/"
cp scripts/bootstrap-ubuntu.sh "$STAGE/"

for arch in amd64 arm64; do
	out=linux-${arch}/${BIN}
	mkdir -p "${STAGE}/$(dirname "$out")"
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 \
		go build -trimpath -ldflags "$LDFLAGS" -o "${STAGE}/${out}" ./cmd/egressvpn
	file "${STAGE}/${out}"
done

# amd64 is the common case, so the tarball root holds it and the arch name only
# appears on the directory, keeping the install path in README short.
cp "${STAGE}/linux-amd64/${BIN}" "${STAGE}/${BIN}"

# COPYFILE_DISABLE stops macOS' bsdtar from embedding Apple xattrs as AppleDouble
# headers: GNU tar on the server prints "Ignoring unknown extended header keyword
# 'LIBARCHIVE.xattr.com.apple.provenance'" for every file, and warnings during an
# install look like a corrupted download.
COPYFILE_DISABLE=1 tar -czf "dist/${BIN}-${VERSION}-linux.tar.gz" -C dist "$(basename "$STAGE")"
rm -rf "$STAGE"

ls -l dist/*.tar.gz
echo
echo "contents:"
tar -tzf "dist/${BIN}-${VERSION}-linux.tar.gz"
