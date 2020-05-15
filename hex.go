package ctrsigcheck

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type Hex []byte

func (h Hex) String() string {
	return strings.ToUpper(hex.EncodeToString(h))
}

func (h Hex) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

type Hex8 uint8

func (h Hex8) String() string {
	return fmt.Sprintf("%02X", uint8(h))
}

func (h Hex8) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

type Hex16 uint16

func (h Hex16) String() string {
	return fmt.Sprintf("%04X", uint16(h))
}

func (h Hex16) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

type Hex32 uint32

func (h Hex32) String() string {
	return fmt.Sprintf("%08X", uint32(h))
}

func (h Hex32) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

type Hex64 uint64

func (h Hex64) String() string {
	return fmt.Sprintf("%016X", uint64(h))
}

func (h Hex64) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}
