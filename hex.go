package ctrsigcheck

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Hex wraps a []byte so that it encodes to hexadecimal.
type Hex []byte

func (h Hex) String() string {
	return strings.ToUpper(hex.EncodeToString(h))
}

// MarshalText implements encoding.TextMarshaler, also used for JSON encoding.
func (h Hex) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// Hex8 wraps an uint8 so that it encodes to hexadecimal.
type Hex8 uint8

func (h Hex8) String() string {
	return fmt.Sprintf("%02X", uint8(h))
}

// MarshalText implements encoding.TextMarshaler, also used for JSON encoding.
func (h Hex8) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// Hex16 wraps an uint16 so that it encodes to hexadecimal.
type Hex16 uint16

func (h Hex16) String() string {
	return fmt.Sprintf("%04X", uint16(h))
}

// MarshalText implements encoding.TextMarshaler, also used for JSON encoding.
func (h Hex16) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// Hex32 wraps an uint32 so that it encodes to hexadecimal.
type Hex32 uint32

func (h Hex32) String() string {
	return fmt.Sprintf("%08X", uint32(h))
}

// MarshalText implements encoding.TextMarshaler, also used for JSON encoding.
func (h Hex32) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// Hex64 wraps an uint64 so that it encodes to hexadecimal.
type Hex64 uint64

func (h Hex64) String() string {
	return fmt.Sprintf("%016X", uint64(h))
}

// MarshalText implements encoding.TextMarshaler, also used for JSON encoding.
func (h Hex64) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}
