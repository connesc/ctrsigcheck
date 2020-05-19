# ctrsigcheck

[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c)](https://pkg.go.dev/mod/github.com/connesc/ctrsigcheck)
[![Go Report Card](https://goreportcard.com/badge/github.com/connesc/ctrsigcheck)](https://goreportcard.com/report/github.com/connesc/ctrsigcheck)
[![GitHub release](https://img.shields.io/github/v/release/connesc/ctrsigcheck)](https://github.com/connesc/ctrsigcheck/releases/latest)
[![License](https://img.shields.io/github/license/connesc/ctrsigcheck)](https://github.com/connesc/ctrsigcheck/blob/master/LICENSE.md)

Parse and verify various file formats used by the Nintendo 3DS, also known as CTR.

This repository contains both a CLI and a Golang library.

## Rationale

The main goal is to check both integrity and authenticity of those files before installing them.

The integrity is established by verifying the file structure and embedded SHA-256 hashes.

While not mandatory, the authenticity can also be established thanks to Nintendo signatures.
Those digital signatures can be verified using public Nintendo certificates, but cannot be
generated without private keys that are only known by Nintendo.

## CLI

The command-line tool can be installed like this:

    go get github.com/connesc/ctrsigcheck/...

## Golang library

Check the [go.dev reference](https://pkg.go.dev/mod/github.com/connesc/ctrsigcheck).

## License

[ISC License](LICENSE)
