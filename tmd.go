package ctrsigcheck

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/connesc/ctrsigcheck/ctrutil"
)

// TMD describes a TMD structure.
type TMD struct {
	Legit        bool
	TitleID      Hex64
	TitleVersion uint16
	Contents     []TMDContent
	CertsTrailer bool
}

// TMDContent describes a content record in a TMD.
type TMDContent struct {
	ID        Hex32
	Index     Hex16
	Type      Hex16
	Size      uint64
	Hash      Hex
	Encrypted bool
	Optional  bool
}

// CheckTMD reads the given TMD file and verifies its content.
//
// It may be followed by a certificate chain. This notably happens for files downloaded from
// Nintendo's CDN. If a certificate chain is found, it is checked against expected content.
//
// A TMD is considered "legit" if its digital signature is properly verified. Unlike other
// checks, signature checks don't produce errors, but instead expose a Legit boolean to the caller.
func CheckTMD(input io.Reader) (*TMD, error) {
	reader := ctrutil.NewReader(input)

	tmdHigh := make([]byte, 0xb04)
	_, err := io.ReadFull(reader, tmdHigh)
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
	contentCount := int(binary.BigEndian.Uint16(header[0x9e:]))

	if !bytes.Equal(sha256Hash(contentInfoRecords), header[0xa4:0xc4]) {
		return nil, fmt.Errorf("tmd: invalid hash for content info records")
	}

	contentChunkRecords := make([]byte, 0x30*contentCount)
	_, err = io.ReadFull(reader, contentChunkRecords)
	if err != nil {
		return nil, fmt.Errorf("tmd: failed to read content chunk records: %w", err)
	}

	contents := make([]TMDContent, 0, contentCount)
	for infoIndex := 0; infoIndex < 64; infoIndex++ {
		infoRecord := contentInfoRecords[infoIndex*0x24 : (infoIndex+1)*0x24]

		firstChunk := len(contents)
		count := int(binary.BigEndian.Uint16(infoRecord[0x2:]))
		if count == 0 {
			continue
		}
		if len(contents)+count > contentCount {
			return nil, fmt.Errorf("tmd: content count exceeded at content info record %d: %d > %d", infoIndex, len(contents)+count, contentCount)
		}

		chunkRecords := contentChunkRecords[0x30*firstChunk : 0x30*(firstChunk+count)]

		if !bytes.Equal(sha256Hash(chunkRecords), infoRecord[0x04:0x24]) {
			return nil, fmt.Errorf("tmd: invalid hash for content chunk records %d to %d", firstChunk, firstChunk+count-1)
		}

		for chunkIndex := 0; chunkIndex < count; chunkIndex++ {
			chunkRecord := chunkRecords[chunkIndex*0x30 : (chunkIndex+1)*0x30]

			contentID := binary.BigEndian.Uint32(chunkRecord)
			contentIndex := binary.BigEndian.Uint16(chunkRecord[0x4:])
			contentType := binary.BigEndian.Uint16(chunkRecord[0x6:])
			contentSize := binary.BigEndian.Uint64(chunkRecord[0x8:])
			contentHash := chunkRecord[0x10:0x30]

			if contentIndex >= 0x2000 {
				return nil, fmt.Errorf("tmd: content index must be less than 0x%04x, got 0x%04x", 0x2000, contentIndex)
			}

			contents = append(contents, TMDContent{
				ID:        Hex32(contentID),
				Index:     Hex16(contentIndex),
				Type:      Hex16(contentType),
				Size:      contentSize,
				Hash:      contentHash,
				Encrypted: contentType&0x0001 != 0,
				Optional:  contentType&0x4000 != 0,
			})
		}
	}

	if len(contents) < contentCount {
		return nil, fmt.Errorf("tmd: content chunk records are fewer than expected: %d < %d", len(contents), contentCount)
	}

	certsTrailer := true
	certs := make([]byte, len(Certs.Retail.CA.Raw)+len(Certs.Retail.TMD.Raw))

	_, err = io.ReadFull(reader, certs)
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

		err = reader.Discard(1)
		if err == nil {
			return nil, fmt.Errorf("tmd: extraneous data after %d bytes", reader.Offset()-1)
		} else if err != io.EOF {
			return nil, fmt.Errorf("tmd: failed to check extraneous data: %w", err)
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
