package ctrsigcheck

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/connesc/ctrsigcheck/ctrutil"
)

type ExeFS struct {
	Icon *SMDH
}

func ParseExeFS(input io.Reader) (*ExeFS, error) {
	reader := ctrutil.NewReader(input)

	header := make([]byte, 0x200)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return nil, fmt.Errorf("exefs: failed to read header: %w", err)
	}

	var iconOffset uint32
	var iconSize uint32

	for i := 0; i < 10; i++ {
		fileHeader := header[i*0x10 : (i+1)*0x10]
		fileName := string(bytes.TrimRight(fileHeader[:0x8], "\x00"))

		if fileName == "icon" {
			iconOffset = binary.LittleEndian.Uint32(fileHeader[0x8:])
			iconSize = binary.LittleEndian.Uint32(fileHeader[0xc:])
		}
	}

	var icon *SMDH

	if iconSize > 0 {
		if iconSize != 0x36c0 {
			return nil, fmt.Errorf("exefs: when present, icon must have size %d, got %d", 0x36c0, iconSize)
		}

		err = reader.Discard(int64(iconOffset))
		if err != nil {
			return nil, fmt.Errorf("exefs: failed to jump to icon: %w", err)
		}

		data := io.LimitReader(reader, int64(iconSize))

		icon, err = ParseSMDH(data)
		if err != nil {
			return nil, err
		}
	}

	return &ExeFS{
		Icon: icon,
	}, nil
}
