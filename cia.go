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
	Legit  bool
	Ticket Ticket
	TMD    TMD
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

	if ticket.TitleID != tmd.TitleID {
		return nil, fmt.Errorf("cia: ticket and TMD have different title IDs: %s != %s", ticket.TitleID, tmd.TitleID)
	}

	legit := ticket.Legit && tmd.Legit

	for _, content := range tmd.Contents {
		size := int64(content.Size)
		if size < 0 {
			return nil, fmt.Errorf("cia: invalid content size: %d", content.Size)
		}

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

	return &CIA{
		Legit:  legit,
		Ticket: *ticket,
		TMD:    *tmd,
	}, nil
}
