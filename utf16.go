package ctrsigcheck

import (
	"encoding/binary"
	"unicode/utf16"
)

func decodeUTF16(src []byte, order binary.ByteOrder) string {
	if len(src)%2 != 0 {
		panic("UTF-16 payload must have an even length")
	}

	dst := make([]uint16, len(src)/2)
	for i := range dst {
		dst[i] = order.Uint16(src[i*2:])
	}

	return string(utf16.Decode(dst))
}
