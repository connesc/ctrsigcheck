package ctrsigcheck

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/connesc/ctrsigcheck/reader"
)

type CIA struct {
	Legit  bool
	Ticket Ticket
	TMD    TMD
}

func CheckCIA(input io.Reader) (*CIA, error) {
	inputReader := reader.New(input)

	header := make([]byte, 0x2020)
	_, err := io.ReadFull(inputReader, header)
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

	err = inputReader.Discard((0x40 - (inputReader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to skip TMD padding: %w", err)
	}

	certs := make([]byte, certsLen)
	_, err = io.ReadFull(inputReader, certs)
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

	err = inputReader.Discard((0x40 - (inputReader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to skip certs padding: %w", err)
	}

	ticket, err := CheckTicket(io.LimitReader(inputReader, int64(ticketLen)))
	if err != nil {
		return nil, err
	}

	if ticket.CertsTrailer {
		return nil, fmt.Errorf("cia: unexpected certs trailer in ticket")
	}

	err = inputReader.Discard((0x40 - (inputReader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to skip ticket padding: %w", err)
	}

	tmd, err := CheckTMD(io.LimitReader(inputReader, int64(tmdLen)))
	if err != nil {
		return nil, err
	}

	if tmd.CertsTrailer {
		return nil, fmt.Errorf("cia: unexpected certs trailer in TMD")
	}

	err = inputReader.Discard((0x40 - (inputReader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, fmt.Errorf("cia: failed to skip TMD padding: %w", err)
	}

	legit := ticket.Legit && tmd.Legit && ticket.TitleID == tmd.TitleID

	return &CIA{
		Legit:  legit,
		Ticket: *ticket,
		TMD:    *tmd,
	}, nil
}
