package ctrsigcheck

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image/png"
	"io"
	"strings"

	"github.com/connesc/ctrsigcheck/ctrutil"
)

// SMDH describes the result of SMDH parsing.
type SMDH struct {
	Title    SMDHTitle
	Regions  []string
	Graphics SMDHGraphics
}

// SMDHTitle describes a title section embedded in a SMDH file.
type SMDHTitle struct {
	ShortDescription string
	LongDescription  string
	Publisher        string
}

// SMDHGraphics contains the PNG-encoded icons embedded in a SMDH file.
type SMDHGraphics struct {
	Small []byte
	Large []byte
}

// ParseSMDH extracts some content from the given SMDH file.
func ParseSMDH(input io.Reader) (*SMDH, error) {
	reader := ctrutil.NewReader(input)

	data := make([]byte, 0x36c0)
	_, err := io.ReadFull(reader, data)
	if err != nil {
		return nil, fmt.Errorf("smdh: failed to read data: %w", err)
	}

	if string(data[:0x4]) != "SMDH" {
		return nil, fmt.Errorf("smdh: magic not found")
	}

	title := data[0x208:0x408]
	shortDescription := strings.TrimRight(ctrutil.DecodeUTF16(title[:0x80], binary.LittleEndian), "\x00")
	longDescription := strings.TrimRight(ctrutil.DecodeUTF16(title[0x80:0x180], binary.LittleEndian), "\x00")
	publisher := strings.TrimRight(ctrutil.DecodeUTF16(title[0x180:0x200], binary.LittleEndian), "\x00")

	regionFlags := binary.LittleEndian.Uint32(data[0x2018:])
	regions := make([]string, 0, 1)
	if regionFlags == 0x7fffffff {
		regions = append(regions, "World")
	} else {
		if regionFlags > 0x7f {
			return nil, fmt.Errorf("smdh: unexpected region flags: %s", Hex32(regionFlags))
		} else if (regionFlags&0x04)<<1 != regionFlags&0x08 {
			return nil, fmt.Errorf("smdh: regions flags must be the same for Europe and Australia: %s", Hex32(regionFlags))
		}
		if regionFlags&0x01 != 0 {
			regions = append(regions, "Japan")
		}
		if regionFlags&0x02 != 0 {
			regions = append(regions, "North America")
		}
		if regionFlags&0x04 != 0 {
			regions = append(regions, "Europe")
		}
		if regionFlags&0x10 != 0 {
			regions = append(regions, "China")
		}
		if regionFlags&0x20 != 0 {
			regions = append(regions, "Korea")
		}
		if regionFlags&0x40 != 0 {
			regions = append(regions, "Taiwan")
		}
	}

	var pngBuffer bytes.Buffer

	rawSmallIcon, err := DecodeIconImage(data[0x2040:0x24c0], 24)
	if err != nil {
		return nil, fmt.Errorf("smdh: failed to decode small icon image: %w", err)
	}
	err = png.Encode(&pngBuffer, rawSmallIcon)
	if err != nil {
		return nil, fmt.Errorf("smdh: failed to encode small icon image: %w", err)
	}
	smallIcon := make([]byte, pngBuffer.Len())
	pngBuffer.Read(smallIcon)

	rawLargeIcon, err := DecodeIconImage(data[0x24c0:0x36c0], 48)
	if err != nil {
		return nil, fmt.Errorf("smdh: failed to decode large icon image: %w", err)
	}
	err = png.Encode(&pngBuffer, rawLargeIcon)
	if err != nil {
		return nil, fmt.Errorf("smdh: failed to encode large icon image: %w", err)
	}
	largeIcon := make([]byte, pngBuffer.Len())
	pngBuffer.Read(largeIcon)

	return &SMDH{
		Title: SMDHTitle{
			ShortDescription: shortDescription,
			LongDescription:  longDescription,
			Publisher:        publisher,
		},
		Regions: regions,
		Graphics: SMDHGraphics{
			Small: smallIcon,
			Large: largeIcon,
		},
	}, nil
}
