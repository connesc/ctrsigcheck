package ctrsigcheck

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/connesc/ctrsigcheck/ctrutil"
)

// CIA describes a CIA file.
type CIA struct {
	Legit    bool
	Complete bool
	TitleID  Hex64
	Ticket   CIATicket
	TMD      CIATMD
	Contents []CIAContent
	Icon     *SMDH
	Meta     bool
}

// CIATicket describes the ticket embedded in a CIA file.
type CIATicket struct {
	Legit     bool
	TicketID  Hex64
	ConsoleID Hex32
	TitleKey  TitleKey
}

// CIATMD describes the TMD embedded in a CIA file.
type CIATMD struct {
	Legit        bool
	TitleVersion uint16
}

// CIAContent describe a content section embedded in a CIA file.
type CIAContent struct {
	Missing bool
	TMDContent
}

// CheckCIA reads the given CIA file and verifies its content.
//
// Many integrity checks are performed, including but not limited to SHA-256 hashes. If any
// problem is detected, an error is immediately returned. Otherwise, a summary of the CIA file is
// returned.
//
// Nintendo signatures are not required to be valid. Their status are made available to the caller
// through the Legit booleans.
//
// A CIA file is considered "legit" if both its ticket and its TMD are "legit". Since the TMD
// contains the hashes of content segments, a "legit" TMD also guarantees a "legit" content. A
// "legit" ticket means that content is legitimately owned, either personnally (e.g. game or update
// downloaded from eShop) or not (e.g. preinstalled game or system title).
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
		if !missing {
			contentsSize += content.Size
		} else if content.Type&0x4000 == 0 {
			return nil, fmt.Errorf("cia: required content %s is missing", content.ID)
		} else {
			complete = false
		}
		contents[index] = CIAContent{
			Missing:    missing,
			TMDContent: content,
		}
	}

	if contentsSize != contentLen {
		return nil, fmt.Errorf("cia: total size of contents does not match expected value: %d != %d", contentsSize, contentLen)
	}

	var icon *SMDH

	for _, content := range contents {
		if content.Missing {
			continue
		}

		if content.Size >= 1<<63 {
			return nil, fmt.Errorf("cia: size of content %s too large: %d", content.ID, content.Size)
		}

		size := int64(content.Size)
		data := io.LimitReader(reader, size)

		if content.Type&0x1 != 0 {
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
		data = io.TeeReader(data, hash)

		dataReader := ctrutil.NewReader(data)
		ncch, err := ParseNCCH(dataReader)
		if err != nil {
			return nil, fmt.Errorf("cia: invalid content %s: %w", content.ID, err)
		}

		if ncch.ProgramID != titleID {
			return nil, fmt.Errorf("cia: content %s has unecpected program ID: %s != %s", content.ID, ncch.ProgramID, titleID)
		}

		if content.Index == 0x0000 && ncch.ExeFS != nil {
			icon = ncch.ExeFS.Icon
		}

		_, err = io.Copy(ioutil.Discard, dataReader)
		if err == nil && dataReader.Offset() < size {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return nil, fmt.Errorf("cia: failed to read content %s: %w", content.ID, err)
		}

		if !bytes.Equal(hash.Sum(nil), content.Hash) {
			return nil, fmt.Errorf("cia: invalid hash for content %s", content.ID)
		}
	}

	meta := metaLen > 0
	if meta {
		if metaLen != 0x3ac0 {
			return nil, fmt.Errorf("cia: when present, meta must have length %d, got %d", 0x3ac0, metaLen)
		}

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
		return nil, fmt.Errorf("cia: extraneous data after %d bytes", reader.Offset()-1)
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
		Icon:     icon,
		Meta:     meta,
	}, nil
}
