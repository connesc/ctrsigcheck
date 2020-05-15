package ctrsigcheck

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type Hex []byte

func (h Hex) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.ToUpper(hex.EncodeToString(h)))
}

type Hex8 uint8

func (h Hex8) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%02X", uint8(h)))
}

type Hex16 uint16

func (h Hex16) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%04X", uint16(h)))
}

type Hex32 uint32

func (h Hex32) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%08X", uint32(h)))
}

type Hex64 uint64

func (h Hex64) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%016X", uint64(h)))
}
