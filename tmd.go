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

func CheckTMD(tmd io.ReaderAt, totalLen uint32) (*TMDInfo, error) {
	if totalLen < 0xb04 {
		return nil, fmt.Errorf("tmd: length must be at least %d, got %d", 0xb04, totalLen)
	}

	var signatureType uint32
	err := binaryReadAt(tmd, 0, binary.BigEndian, &signatureType)
	if err != nil {
		return nil, err
	}

	if signatureType != 0x10004 {
		return nil, fmt.Errorf("tmd: signature type must be 0x%08x, got 0x%08x", 0x10004, signatureType)
	}

	signature := make([]byte, 0x100)
	_, err = tmd.ReadAt(signature, 0x4)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 0xc4)
	_, err = tmd.ReadAt(header, 0x140)
	if err != nil {
		return nil, err
	}

	issuer := string(bytes.TrimRight(header[:0x40], "\x00"))
	legit := issuer == fmt.Sprintf("Root-%s-%s", Certs.Retail.CA.Name, Certs.Retail.TMD.Name)

	if legit {
		legit = rsa.VerifyPKCS1v15(&Certs.Retail.TMD.PublicKey, crypto.SHA256, sha256Hash(header), signature) == nil
	}

	titleID := strings.ToUpper(hex.EncodeToString(header[0x4c:0x54]))

	var titleVersion uint16
	err = binary.Read(bytes.NewReader(header[0x9c:]), binary.BigEndian, &titleVersion)
	if err != nil {
		return nil, err
	}

	var contentCount uint16
	err = binary.Read(bytes.NewReader(header[0x9e:]), binary.BigEndian, &contentCount)
	if err != nil {
		return nil, err
	}

	contentRecordsLen := 0x900 + 0x30*uint32(contentCount)
	tmdLen := 0x204 + contentRecordsLen
	certsTrailerLen := uint32(len(Certs.Retail.CA.Raw) + len(Certs.Retail.TMD.Raw))

	var certsTrailer bool
	switch totalLen {
	case tmdLen:
		certsTrailer = false
	case tmdLen + certsTrailerLen:
		certsTrailer = true
	default:
		return nil, fmt.Errorf("tmd: length must be either %d or %d, got %d", tmdLen, tmdLen+certsTrailerLen, totalLen)
	}

	contentRecords := make([]byte, contentRecordsLen)
	_, err = tmd.ReadAt(contentRecords, 0x204)
	if err != nil {
		return nil, err
	}

	if legit {
		legit = bytes.Equal(sha256Hash(contentRecords[:0x900]), header[0xa4:0xc4])
	}

	contents := make([]TMDContent, 0, contentCount)
	for infoIndex := 0; infoIndex < 64; infoIndex++ {
		infoRecord := contentRecords[infoIndex*0x24 : (infoIndex+1)*0x24]

		var count uint16
		err = binary.Read(bytes.NewReader(infoRecord[0x2:]), binary.BigEndian, &count)
		if err != nil {
			return nil, err
		}

		if count == 0 {
			continue
		}

		chunkRecordsOffset := 0x900 + 0x30*len(contents)
		chunkRecords := contentRecords[chunkRecordsOffset : chunkRecordsOffset+0x30*int(count)]

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
				return nil, err
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

	if certsTrailer {
		certs := make([]byte, certsTrailerLen)
		_, err = tmd.ReadAt(certs, int64(tmdLen))
		if err != nil {
			return nil, err
		}

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
