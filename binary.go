package ctrsigcheck

import (
	"encoding/binary"
	"io"
)

func binaryReadAt(reader io.ReaderAt, offset int64, order binary.ByteOrder, data interface{}) error {
	return binary.Read(io.NewSectionReader(reader, offset, int64(binary.Size(data))), order, data)
}
