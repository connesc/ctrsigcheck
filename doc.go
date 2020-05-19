// Package ctrsigcheck allows to parse and verify various file formats used by the Nintendo 3DS,
// also known as CTR.
//
// The main goal is to check both integrity and authenticity of those files before installing them.
// The integrity is established by verifying the file structure and embedded SHA-256 hashes.
// While not mandatory, the authenticity can also be established thanks to Nintendo signatures.
// Those digital signatures can be verified using public Nintendo certificates, but cannot be
// generated without private keys that are only known by Nintendo.
//
// This package comes with a CLI. You can install it like this:
//   go get github.com/connesc/ctrsigcheck/cmd/ctrsigcheck
package ctrsigcheck
