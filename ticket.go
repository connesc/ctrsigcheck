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

type TicketInfo struct {
	Legit        bool
	TicketID     string
	ConsoleID    string
	TitleID      string
	TitleKey     string
	CertsTrailer bool
}

func CheckTicket(input io.Reader) (*TicketInfo, error) {
	inputReader := reader.New(input)

	ticket := make([]byte, 0x350)
	_, err := io.ReadFull(inputReader, ticket)
	if err != nil {
		return nil, fmt.Errorf("ticket: failed to read ticket: %w", err)
	}

	var signatureType uint32
	err = binary.Read(bytes.NewReader(ticket), binary.BigEndian, &signatureType)
	if err != nil {
		return nil, fmt.Errorf("ticket: failed to parse signature type: %w", err)
	}

	if signatureType != 0x10004 {
		return nil, fmt.Errorf("ticket: signature type must be 0x%08x, got 0x%08x", 0x10004, signatureType)
	}

	signature := ticket[0x4:0x104]
	data := ticket[0x140:]

	issuer := string(bytes.TrimRight(data[:0x40], "\x00"))
	legit := issuer == fmt.Sprintf("Root-%s-%s", Certs.Retail.CA.Name, Certs.Retail.Ticket.Name)

	if legit {
		legit = rsa.VerifyPKCS1v15(&Certs.Retail.Ticket.PublicKey, crypto.SHA256, sha256Hash(data), signature) == nil
	}

	titleKey := strings.ToUpper(hex.EncodeToString(data[0x7f:0x8f]))
	ticketID := strings.ToUpper(hex.EncodeToString(data[0x90:0x98]))
	consoleID := strings.ToUpper(hex.EncodeToString(data[0x98:0x9c]))
	titleID := strings.ToUpper(hex.EncodeToString(data[0x9c:0xa4]))

	certsTrailer := true
	certs := make([]byte, len(Certs.Retail.CA.Raw)+len(Certs.Retail.Ticket.Raw))

	_, err = io.ReadFull(inputReader, certs)
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
	}

	err = inputReader.Discard(1)
	if err == nil {
		return nil, fmt.Errorf("ticket: extraneous data after %d bytes", inputReader.Offset())
	} else if err != io.EOF {
		return nil, fmt.Errorf("ticket: failed to check extraneous data: %w", err)
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
