# ctrsigcheck

[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c)](https://pkg.go.dev/github.com/connesc/ctrsigcheck)
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

### Installation

The command-line tool can be found precompiled in the [releases page](https://github.com/connesc/ctrsigcheck/releases).

Alternatively, it can be built and installed from source:

    go get github.com/connesc/ctrsigcheck/cmd/ctrsigcheck

An AUR package is also available for Arch Linux users: [ctrsigcheck-bin](https://aur.archlinux.org/packages/ctrsigcheck-bin/).

### Usage

```
Parse and verify various file formats used by the Nintendo 3DS, also known as CTR

Usage:
  ctrsigcheck [command]

Available Commands:
  cia         Check CIA files
  help        Help about any command
  ticket      Check ticket files
  tmd         Check TMD files

Flags:
  -h, --help   help for ctrsigcheck

Use "ctrsigcheck [command] --help" for more information about a command.
```

## Golang library

Check the [go.dev reference](https://pkg.go.dev/github.com/connesc/ctrsigcheck).

## License

[ISC License](LICENSE)
