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

type TicketInfo struct {
	Legit        bool
	TicketID     string
	ConsoleID    string
	TitleID      string
	TitleKey     string
	CertsTrailer bool
}

func CheckTicket(ticket io.ReaderAt, totalLen uint32) (*TicketInfo, error) {
	ticketLen := uint32(0x350)
	certsTrailerLen := uint32(len(Certs.Retail.CA.Raw) + len(Certs.Retail.Ticket.Raw))

	var certsTrailer bool
	switch totalLen {
	case ticketLen:
		certsTrailer = false
	case ticketLen + certsTrailerLen:
		certsTrailer = true
	default:
		return nil, fmt.Errorf("ticket: length must be either %d or %d, got %d", ticketLen, ticketLen+certsTrailerLen, totalLen)
	}

	var signatureType uint32
	err := binaryReadAt(ticket, 0, binary.BigEndian, &signatureType)
	if err != nil {
		return nil, err
	}

	if signatureType != 0x10004 {
		return nil, fmt.Errorf("ticket: signature type must be 0x%08x, got 0x%08x", 0x10004, signatureType)
	}

	signature := make([]byte, 0x100)
	_, err = ticket.ReadAt(signature, 0x4)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0x210)
	_, err = ticket.ReadAt(data, 0x140)
	if err != nil {
		return nil, err
	}

	issuer := string(bytes.TrimRight(data[:0x40], "\x00"))
	legit := issuer == fmt.Sprintf("Root-%s-%s", Certs.Retail.CA.Name, Certs.Retail.Ticket.Name)

	if legit {
		legit = rsa.VerifyPKCS1v15(&Certs.Retail.Ticket.PublicKey, crypto.SHA256, sha256Hash(data), signature) == nil
	}

	titleKey := strings.ToUpper(hex.EncodeToString(data[0x7f:0x8f]))
	ticketID := strings.ToUpper(hex.EncodeToString(data[0x90:0x98]))
	consoleID := strings.ToUpper(hex.EncodeToString(data[0x98:0x9c]))
	titleID := strings.ToUpper(hex.EncodeToString(data[0x9c:0xa4]))

	if certsTrailer {
		certs := make([]byte, certsTrailerLen)
		_, err = ticket.ReadAt(certs, int64(ticketLen))
		if err != nil {
			return nil, err
		}

		ticketCertLen := len(Certs.Retail.Ticket.Raw)
		if !bytes.Equal(certs[:ticketCertLen], Certs.Retail.Ticket.Raw) {
			return nil, fmt.Errorf("ticket: invalid ticket certificate in trailer")
		}

		caCertLen := len(Certs.Retail.CA.Raw)
		if !bytes.Equal(certs[ticketCertLen:ticketCertLen+caCertLen], Certs.Retail.CA.Raw) {
			return nil, fmt.Errorf("ticket: invalid CA certificate in trailer")
		}
	}

	return &TicketInfo{
		Legit:        legit,
		TicketID:     ticketID,
		ConsoleID:    consoleID,
		TitleID:      titleID,
		TitleKey:     titleKey,
		CertsTrailer: certsTrailer,
	}, nil
}
