package ctrsigcheck

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/connesc/ctrsigcheck/ctrutil"
)

type NCCH struct {
	PartitionID Hex64
	ProgramID   Hex64
	ExeFS       *ExeFS
}

func ParseNCCH(input io.Reader) (*NCCH, error) {
	reader := ctrutil.NewReader(input)

	header := make([]byte, 0x1e0)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return nil, fmt.Errorf("ncch: failed to read header: %w", err)
	}

	signature := header[:0x100]

	if string(header[0x100:0x104]) != "NCCH" {
		return nil, fmt.Errorf("ncch: magic not found")
	}

	partitionID := binary.LittleEndian.Uint64(header[0x108:])
	programID := binary.LittleEndian.Uint64(header[0x118:])

	version := binary.LittleEndian.Uint16(header[0x112:])
	if version >= 3 {
		return nil, fmt.Errorf("ncch: version must be less than 3: %d", version)
	}

	flags := header[0x188:0x190]
	exefsOffset := int64(binary.LittleEndian.Uint32(header[0x1a0:])) * 0x200
	exefsSize := int64(binary.LittleEndian.Uint32(header[0x1a4:])) * 0x200

	var exefs *ExeFS

	if exefsSize > 0 {
		err = reader.Discard(int64(exefsOffset) - reader.Offset())
		if err != nil {
			return nil, fmt.Errorf("ncch: failed to jump to ExeFS: %w", err)
		}

		data := io.LimitReader(reader, exefsSize)

		if flags[7]&0x4 == 0 {
			var key []byte
			switch {
			case flags[7]&0x1 == 0:
				key = keygen(ncchKeyX, signature[:0x10])
			case partitionID&1000000000 != 0:
				key = fixedSystemKey
			default:
				key = zeroKey
			}

			exefsCipher, err := aes.NewCipher(key)
			if err != nil {
				return nil, fmt.Errorf("ncch: failed to initialize ExeFS cipher: %w", err)
			}
			exefsIV := make([]byte, exefsCipher.BlockSize())
			if version == 1 {
				binary.LittleEndian.PutUint64(exefsIV, partitionID)
				binary.BigEndian.PutUint64(exefsIV, uint64(exefsOffset))
			} else {
				binary.BigEndian.PutUint64(exefsIV, partitionID)
				exefsIV[8] = 2
			}
			data = cipher.StreamReader{
				S: cipher.NewCTR(exefsCipher, exefsIV),
				R: data,
			}
		}

		exefs, err = ParseExeFS(data)
		if err != nil {
			return nil, err
		}
	}

	return &NCCH{
		PartitionID: Hex64(partitionID),
		ProgramID:   Hex64(programID),
		ExeFS:       exefs,
	}, nil
}
