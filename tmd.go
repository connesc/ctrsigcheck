package ctrsigcheck

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/connesc/ctrsigcheck/reader"
)

type TMD struct {
	Legit        bool
	TitleID      Hex64
	TitleVersion uint16
	Contents     []TMDContent
	CertsTrailer bool
}

type TMDContent struct {
	ID    Hex32
	Index Hex16
	Type  Hex16
	Size  uint64
	Hash  Hex
}

func CheckTMD(input io.Reader) (*TMD, error) {
	inputReader := reader.New(input)

	tmdHigh := make([]byte, 0xb04)
	_, err := io.ReadFull(inputReader, tmdHigh)
	if err != nil {
		return nil, fmt.Errorf("tmd: failed to read first part of TMD: %w", err)
	}

	signatureType := binary.BigEndian.Uint32(tmdHigh)
	if signatureType != 0x10004 {
		return nil, fmt.Errorf("tmd: signature type must be 0x%08x, got 0x%08x", 0x10004, signatureType)
	}

	signature := tmdHigh[0x4:0x104]
	header := tmdHigh[0x140:0x204]
	contentInfoRecords := tmdHigh[0x204:]

	issuer := string(bytes.TrimRight(header[:0x40], "\x00"))
	if issuer != fmt.Sprintf("Root-%s-%s", Certs.Retail.CA.Name, Certs.Retail.TMD.Name) {
		return nil, fmt.Errorf("tmd: unexpected issuer: %s", issuer)
	}

	legit := rsa.VerifyPKCS1v15(&Certs.Retail.TMD.PublicKey, crypto.SHA256, sha256Hash(header), signature) == nil

	titleID := binary.BigEndian.Uint64(header[0x4c:])
	titleVersion := binary.BigEndian.Uint16(header[0x9c:])
	contentCount := binary.BigEndian.Uint16(header[0x9e:])

	if !bytes.Equal(sha256Hash(contentInfoRecords), header[0xa4:0xc4]) {
		return nil, fmt.Errorf("tmd: invalid hash for content info records")
	}

	contentChunkRecords := make([]byte, 0x30*uint32(contentCount))
	_, err = io.ReadFull(inputReader, contentChunkRecords)
	if err != nil {
		return nil, fmt.Errorf("tmd: failed to read TMD content chunk records: %w", err)
	}

	contents := make([]TMDContent, 0, contentCount)
	for infoIndex := 0; infoIndex < 64; infoIndex++ {
		infoRecord := contentInfoRecords[infoIndex*0x24 : (infoIndex+1)*0x24]

		fisrtChunk := len(contents)
		count := int(binary.BigEndian.Uint16(infoRecord[0x2:]))
		if count == 0 {
			continue
		}

		chunkRecords := contentChunkRecords[0x30*fisrtChunk : 0x30*(fisrtChunk+count)]

		if !bytes.Equal(sha256Hash(chunkRecords), infoRecord[0x04:0x24]) {
			return nil, fmt.Errorf("tmd: invalid hash for content chunk records %d to %d", fisrtChunk, fisrtChunk+count-1)
		}

		for chunkIndex := 0; chunkIndex < count; chunkIndex++ {
			chunkRecord := chunkRecords[chunkIndex*0x30 : (chunkIndex+1)*0x30]

			contentID := binary.BigEndian.Uint32(chunkRecord)
			contentIndex := binary.BigEndian.Uint16(chunkRecord[0x4:])
			contentType := binary.BigEndian.Uint16(chunkRecord[0x6:])
			contentSize := binary.BigEndian.Uint64(chunkRecord[0x8:])
			contentHash := chunkRecord[0x10:0x30]

			contents = append(contents, TMDContent{
				ID:    Hex32(contentID),
				Index: Hex16(contentIndex),
				Type:  Hex16(contentType),
				Size:  contentSize,
				Hash:  contentHash,
			})
		}
	}

	certsTrailer := true
	certs := make([]byte, len(Certs.Retail.CA.Raw)+len(Certs.Retail.TMD.Raw))

	_, err = io.ReadFull(inputReader, certs)
	if err == io.EOF {
		certsTrailer = false
	} else if err != nil {
		return nil, fmt.Errorf("tmd: failed to read certs trailer: %w", err)
	}

	if certsTrailer {
		tmdCertLen := len(Certs.Retail.TMD.Raw)
		if !bytes.Equal(certs[:tmdCertLen], Certs.Retail.TMD.Raw) {
			return nil, fmt.Errorf("tmd: invalid TMD certificate in trailer")
		}

		caCertLen := len(Certs.Retail.CA.Raw)
		if !bytes.Equal(certs[tmdCertLen:tmdCertLen+caCertLen], Certs.Retail.CA.Raw) {
			return nil, fmt.Errorf("tmd: invalid CA certificate in trailer")
		}
	}

	return &TMD{
		Legit:        legit,
		TitleID:      Hex64(titleID),
		TitleVersion: titleVersion,
		Contents:     contents,
		CertsTrailer: certsTrailer,
	}, nil
}
