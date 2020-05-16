package ctrsigcheck

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/connesc/ctrsigcheck/ctrutil"
)

type CIA struct {
	Legit    bool
	Complete bool
	TitleID  Hex64
	Ticket   CIATicket
	TMD      CIATMD
	Contents []CIAContent
	MetaSize uint32
}

type CIATicket struct {
	Legit     bool
	TicketID  Hex64
	ConsoleID Hex32
	TitleKey  TitleKey
}

type CIATMD struct {
	Legit        bool
	TitleVersion uint16
}

type CIAContent struct {
	Missing bool
	TMDContent
}

func CheckCIA(input io.Reader) (*CIA, error) {
	reader := ctrutil.NewReader(input)

	header := make([]byte, 0x2020)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to read header: %w", err)
	}

	headerLen := binary.LittleEndian.Uint32(header)
	if headerLen != 0x2020 {
		return nil, fmt.Errorf("cia: header length must be %d, got %d", 0x2020, headerLen)
	}

	certsLen := binary.LittleEndian.Uint32(header[0x8:])
	ticketLen := binary.LittleEndian.Uint32(header[0xc:])
	tmdLen := binary.LittleEndian.Uint32(header[0x10:])
	metaLen := binary.LittleEndian.Uint32(header[0x14:])
	contentLen := binary.LittleEndian.Uint64(header[0x18:])
	contentIndex := header[0x20:]

	expectedCertsLen := uint32(len(Certs.Retail.CA.Raw) + len(Certs.Retail.Ticket.Raw) + len(Certs.Retail.TMD.Raw))
	if certsLen != expectedCertsLen {
		return nil, fmt.Errorf("cia: certs length must be %d, got %d", expectedCertsLen, certsLen)
	}

	err = reader.Discard((0x40 - (reader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to skip TMD padding: %w", err)
	}

	certs := make([]byte, certsLen)
	_, err = io.ReadFull(reader, certs)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to read certs: %w", err)
	}

	caCertLen := len(Certs.Retail.CA.Raw)
	if !bytes.Equal(certs[:caCertLen], Certs.Retail.CA.Raw) {
		return nil, fmt.Errorf("cia: invalid CA certificate")
	}

	ticketCertLen := len(Certs.Retail.Ticket.Raw)
	if !bytes.Equal(certs[caCertLen:caCertLen+ticketCertLen], Certs.Retail.Ticket.Raw) {
		return nil, fmt.Errorf("cia: invalid ticket certificate")
	}

	tmdCertLen := len(Certs.Retail.TMD.Raw)
	if !bytes.Equal(certs[caCertLen+ticketCertLen:caCertLen+ticketCertLen+tmdCertLen], Certs.Retail.TMD.Raw) {
		return nil, fmt.Errorf("cia: invalid TMD certificate")
	}

	err = reader.Discard((0x40 - (reader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to skip certs padding: %w", err)
	}

	ticket, err := CheckTicket(io.LimitReader(reader, int64(ticketLen)))
	if err != nil {
		return nil, err
	}

	if ticket.CertsTrailer {
		return nil, fmt.Errorf("cia: unexpected certs trailer in ticket")
	}

	err = reader.Discard((0x40 - (reader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to skip ticket padding: %w", err)
	}

	tmd, err := CheckTMD(io.LimitReader(reader, int64(tmdLen)))
	if err != nil {
		return nil, err
	}

	if tmd.CertsTrailer {
		return nil, fmt.Errorf("cia: unexpected certs trailer in TMD")
	}

	err = reader.Discard((0x40 - (reader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to skip TMD padding: %w", err)
	}

	titleID := tmd.TitleID
	if ticket.TitleID != titleID {
		return nil, fmt.Errorf("cia: ticket and TMD have different title IDs: %s != %s", ticket.TitleID, tmd.TitleID)
	}

	legit := ticket.Legit && tmd.Legit

	indexLen := (len(tmd.Contents) + 7) / 8
	lastIndexBits := len(tmd.Contents) % 8
	if lastIndexBits != 0 {
		if contentIndex[indexLen-1]<<lastIndexBits != 0 {
			return nil, fmt.Errorf("cia: content index contains more than %d entries", len(tmd.Contents))
		}
	}
	for _, indexByte := range contentIndex[indexLen:] {
		if indexByte != 0 {
			return nil, fmt.Errorf("cia: content index contains more than %d entries", len(tmd.Contents))
		}
	}

	contents := make([]CIAContent, len(tmd.Contents))
	contentsSize := uint64(0)
	complete := true
	for index, content := range tmd.Contents {
		missing := contentIndex[content.Index/8]&(1<<(7-(content.Index%8))) == 0
		if missing {
			complete = false
		} else {
			contentsSize += content.Size
		}
		contents[index] = CIAContent{
			Missing:    missing,
			TMDContent: content,
		}
	}

	if contentsSize != contentLen {
		return nil, fmt.Errorf("cia: total size of contents does not match expected value: %d != %d", contentsSize, contentLen)
	}

	for _, content := range contents {
		if content.Missing {
			continue
		}

		if content.Size >= 1<<63 {
			return nil, fmt.Errorf("cia: size of content %s too large: %d", content.ID, content.Size)
		}

		size := int64(content.Size)
		data := io.LimitReader(reader, size)
		endOffset := reader.Offset() + size

		if content.Type&0x1 == 1 {
			contentCipher, err := aes.NewCipher(ticket.TitleKey.Decrypted)
			if err != nil {
				return nil, fmt.Errorf("cia: failed to initialize AES cipher for content %s: %w", content.ID, err)
			}
			if size%int64(contentCipher.BlockSize()) != 0 {
				return nil, fmt.Errorf("cia: length of content %s must be a multiple of the AES block size: %d %% %d != 0", content.ID, size, contentCipher.BlockSize())
			}
			contentIV := make([]byte, contentCipher.BlockSize())
			binary.BigEndian.PutUint16(contentIV, uint16(content.Index))
			data = ctrutil.NewCipherReader(data, cipher.NewCBCDecrypter(contentCipher, contentIV))
		}

		hash := sha256.New()
		_, err = io.Copy(hash, data)
		if reader.Offset() < endOffset {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return nil, fmt.Errorf("cia: failed to read content %s: %w", content.ID, err)
		}

		if !bytes.Equal(hash.Sum(nil), content.Hash) {
			return nil, fmt.Errorf("cia: invalid hash for content %s", content.ID)
		}
	}

	if metaLen > 0 {
		err = reader.Discard((0x40 - (reader.Offset() % 0x40)) % 0x40)
		if err != nil {
			return nil, fmt.Errorf("cia: failed to skip contents padding: %w", err)
		}

		err = reader.Discard(int64(metaLen))
		if err != nil {
			return nil, fmt.Errorf("cia: failed to read meta")
		}
	}

	err = reader.Discard(1)
	if err == nil {
		return nil, fmt.Errorf("cia: extraneous data after %d bytes", reader.Offset())
	} else if err != io.EOF {
		return nil, fmt.Errorf("cia: failed to check extraneous data: %w", err)
	}

	return &CIA{
		Legit:    legit,
		Complete: complete,
		TitleID:  titleID,
		Ticket: CIATicket{
			Legit:     ticket.Legit,
			TicketID:  ticket.TicketID,
			ConsoleID: ticket.ConsoleID,
			TitleKey:  ticket.TitleKey,
		},
		TMD: CIATMD{
			Legit:        tmd.Legit,
			TitleVersion: tmd.TitleVersion,
		},
		Contents: contents,
		MetaSize: metaLen,
	}, nil
}
