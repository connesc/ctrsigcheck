package ctrsigcheck

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/connesc/ctrsigcheck/ctrutil"
)

type TitleKey struct {
	Encrypted Hex
	Decrypted Hex
}

type Ticket struct {
	Legit        bool
	TicketID     Hex64
	ConsoleID    Hex32
	TitleID      Hex64
	TitleKey     TitleKey
	CertsTrailer bool
}

func CheckTicket(input io.Reader) (*Ticket, error) {
	reader := ctrutil.NewReader(input)

	ticket := make([]byte, 0x350)
	_, err := io.ReadFull(reader, ticket)
	if err != nil {
		return nil, fmt.Errorf("ticket: failed to read ticket: %w", err)
	}

	signatureType := binary.BigEndian.Uint32(ticket)
	if signatureType != 0x10004 {
		return nil, fmt.Errorf("ticket: signature type must be 0x%08x, got 0x%08x", 0x10004, signatureType)
	}

	signature := ticket[0x4:0x104]
	data := ticket[0x140:]

	issuer := string(bytes.TrimRight(data[:0x40], "\x00"))
	if issuer != fmt.Sprintf("Root-%s-%s", Certs.Retail.CA.Name, Certs.Retail.Ticket.Name) {
		return nil, fmt.Errorf("ticket: unexpected issuer: %s", issuer)
	}

	legit := rsa.VerifyPKCS1v15(&Certs.Retail.Ticket.PublicKey, crypto.SHA256, sha256Hash(data), signature) == nil

	ticketID := binary.BigEndian.Uint64(data[0x90:])
	consoleID := binary.BigEndian.Uint32(data[0x98:])
	titleID := binary.BigEndian.Uint64(data[0x9c:])

	encryptedTitleKey := data[0x7f:0x8f]

	commonKeyIndex := int(data[0xb1])
	if commonKeyIndex >= len(commonKeys) {
		return nil, fmt.Errorf("ticket: common key index must be less than %d, got %d", len(commonKeys), commonKeyIndex)
	}

	titleKeyCipher, err := aes.NewCipher(commonKeys[commonKeyIndex])
	if err != nil {
		return nil, fmt.Errorf("ticket: failed to initialize title key decryption: %w", err)
	}
	titleKeyIV := make([]byte, titleKeyCipher.BlockSize())
	binary.BigEndian.PutUint64(titleKeyIV, titleID)
	titleKeyDecrypter := cipher.NewCBCDecrypter(titleKeyCipher, titleKeyIV)

	decryptedTitleKey := make([]byte, 0x10)
	titleKeyDecrypter.CryptBlocks(decryptedTitleKey, encryptedTitleKey)

	certsTrailer := true
	certs := make([]byte, len(Certs.Retail.CA.Raw)+len(Certs.Retail.Ticket.Raw))

	_, err = io.ReadFull(reader, certs)
	if err == io.EOF {
		certsTrailer = false
	} else if err != nil {
		return nil, fmt.Errorf("ticket: failed to read certs trailer: %w", err)
	}

	if certsTrailer {
		ticketCertLen := len(Certs.Retail.Ticket.Raw)
		if !bytes.Equal(certs[:ticketCertLen], Certs.Retail.Ticket.Raw) {
			return nil, fmt.Errorf("ticket: invalid ticket certificate in trailer")
		}

		caCertLen := len(Certs.Retail.CA.Raw)
		if !bytes.Equal(certs[ticketCertLen:ticketCertLen+caCertLen], Certs.Retail.CA.Raw) {
			return nil, fmt.Errorf("ticket: invalid CA certificate in trailer")
		}

		err = reader.Discard(1)
		if err == nil {
			return nil, fmt.Errorf("ticket: extraneous data after %d bytes", reader.Offset()-1)
		} else if err != io.EOF {
			return nil, fmt.Errorf("ticket: failed to check extraneous data: %w", err)
		}
	}

	return &Ticket{
		Legit:     legit,
		TicketID:  Hex64(ticketID),
		ConsoleID: Hex32(consoleID),
		TitleID:   Hex64(titleID),
		TitleKey: TitleKey{
			Encrypted: encryptedTitleKey,
			Decrypted: decryptedTitleKey,
		},
		CertsTrailer: certsTrailer,
	}, nil
}
