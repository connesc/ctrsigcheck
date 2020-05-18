package ctrsigcheck

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"math"
)

var five2eight [1 << 5]uint8
var six2eight [1 << 6]uint8

var iconBlock [1 << 6]int

func init() {
	for i := range five2eight {
		five2eight[i] = uint8(math.Round(float64(i) * 255.0 / 31.0))
	}
	for i := range six2eight {
		six2eight[i] = uint8(math.Round(float64(i) * 255.0 / 63.0))
	}
	for i := range iconBlock {
		// Swap bits: 5 4 3 2 1 0 => 5 3 1 4 2 0
		iconBlock[i] = i&33 | (i&16)>>2 | (i&8)<<1 | (i&4)>>1 | (i&2)<<2
	}
}

func DecodeIconImage(src []byte, width int) (image.Image, error) {
	if width <= 0 || width%8 != 0 {
		return nil, fmt.Errorf("icon width must be positive and multiple of 8, got %d", width)
	}
	n := len(src)
	if n == 0 || n%(16*width) != 0 {
		return nil, fmt.Errorf("icon length must be positive and multiple of %d (16*width), got %d", 16*width, n)
	}

	pixels := n / 2
	height := pixels / width
	dst := image.NewNRGBA(image.Rectangle{Max: image.Pt(width, height)})

	widthBlocks := width / 8

	for i := 0; i < pixels; i++ {
		pixel := binary.LittleEndian.Uint16(src[2*i:])

		block := i / 64
		blockIndex := iconBlock[i%64]

		x := 8*(block%widthBlocks) + blockIndex%8
		y := 8*(block/widthBlocks) + blockIndex/8
		c := color.NRGBA{
			R: five2eight[pixel>>11],
			G: six2eight[(pixel>>5)&0x3f],
			B: five2eight[pixel&0x1f],
			A: 255,
		}
		dst.Set(x, y, c)
	}

	return dst, nil
}
