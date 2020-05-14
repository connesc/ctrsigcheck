package ctrsigcheck

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/connesc/ctrsigcheck/reader"
)

type TMDInfo struct {
	Legit        bool
	TitleID      string
	TitleVersion uint16
	Contents     []TMDContent
	CertsTrailer bool
}

type TMDContent struct {
	ID    string
	Index string
	Type  string
	Size  uint64
	Hash  string
}

func CheckTMD(input io.Reader) (*TMDInfo, error) {
	inputReader := reader.New(input)

	tmdHigh := make([]byte, 0xb04)
	_, err := io.ReadFull(inputReader, tmdHigh)
	if err != nil {
		return nil, fmt.Errorf("tmd: failed to read first part of TMD: %w", err)
	}

	var signatureType uint32
	err = binary.Read(bytes.NewReader(tmdHigh), binary.BigEndian, &signatureType)
	if err != nil {
		return nil, fmt.Errorf("tmd: failed to parse signature type: %w", err)
	}

	if signatureType != 0x10004 {
		return nil, fmt.Errorf("tmd: signature type must be 0x%08x, got 0x%08x", 0x10004, signatureType)
	}

	signature := tmdHigh[0x4:0x104]
	header := tmdHigh[0x140:0x204]
	contentInfoRecords := tmdHigh[0x204:]

	issuer := string(bytes.TrimRight(header[:0x40], "\x00"))
	legit := issuer == fmt.Sprintf("Root-%s-%s", Certs.Retail.CA.Name, Certs.Retail.TMD.Name)

	if legit {
		legit = rsa.VerifyPKCS1v15(&Certs.Retail.TMD.PublicKey, crypto.SHA256, sha256Hash(header), signature) == nil
	}

	titleID := strings.ToUpper(hex.EncodeToString(header[0x4c:0x54]))

	var titleVersion uint16
	err = binary.Read(bytes.NewReader(header[0x9c:]), binary.BigEndian, &titleVersion)
	if err != nil {
		return nil, fmt.Errorf("tmd: failed to parse title version: %w", err)
	}

	var contentCount uint16
	err = binary.Read(bytes.NewReader(header[0x9e:]), binary.BigEndian, &contentCount)
	if err != nil {
		return nil, fmt.Errorf("tmd: failed to parse content count: %w", err)
	}

	if legit {
		legit = bytes.Equal(sha256Hash(contentInfoRecords), header[0xa4:0xc4])
	}

	contentChunkRecords := make([]byte, 0x30*uint32(contentCount))
	_, err = io.ReadFull(inputReader, contentChunkRecords)
	if err != nil {
		return nil, fmt.Errorf("tmd: failed to read TMD content chunk records: %w", err)
	}

	contents := make([]TMDContent, 0, contentCount)
	for infoIndex := 0; infoIndex < 64; infoIndex++ {
		infoRecord := contentInfoRecords[infoIndex*0x24 : (infoIndex+1)*0x24]

		var count uint16
		err = binary.Read(bytes.NewReader(infoRecord[0x2:]), binary.BigEndian, &count)
		if err != nil {
			return nil, fmt.Errorf("tmd: failed to parse count from content info record %d: %w", infoIndex, err)
		}

		if count == 0 {
			continue
		}

		chunkRecords := contentChunkRecords[0x30*len(contents) : 0x30*(len(contents)+int(count))]

		if legit {
			legit = bytes.Equal(sha256Hash(chunkRecords), infoRecord[0x04:0x24])
		}

		for chunkIndex := 0; chunkIndex < int(count); chunkIndex++ {
			chunkRecord := chunkRecords[chunkIndex*0x30 : (chunkIndex+1)*0x30]

			contentID := strings.ToUpper(hex.EncodeToString(chunkRecord[0:0x4]))
			contentIndex := strings.ToUpper(hex.EncodeToString(chunkRecord[0x4:0x6]))
			contentType := strings.ToUpper(hex.EncodeToString(chunkRecord[0x6:0x8]))

			var contentSize uint64
			err = binary.Read(bytes.NewReader(chunkRecord[0x8:]), binary.BigEndian, &contentSize)
			if err != nil {
				return nil, fmt.Errorf("tmd: failed to parse content size from content chunk record %d: %w", chunkIndex, err)
			}

			contentHash := strings.ToUpper(hex.EncodeToString(chunkRecord[0x10:0x30]))

			contents = append(contents, TMDContent{
				ID:    contentID,
				Index: contentIndex,
				Type:  contentType,
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

	return &TMDInfo{
		Legit:        legit,
		TitleID:      titleID,
		TitleVersion: titleVersion,
		Contents:     contents,
		CertsTrailer: certsTrailer,
	}, nil
}
