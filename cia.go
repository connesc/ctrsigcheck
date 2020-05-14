package ctrsigcheck

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/connesc/ctrsigcheck/reader"
)

type CIAInfo struct {
	Legit  bool
	Ticket TicketInfo
	TMD    TMDInfo
}

func CheckCIA(input io.Reader) (*CIAInfo, error) {
	inputReader := reader.New(input)

	header := make([]byte, 0x2020)
	_, err := io.ReadFull(inputReader, header)
	if err != nil {
		return nil, err
	}

	var headerLen uint32
	err = binary.Read(bytes.NewReader(header), binary.LittleEndian, &headerLen)
	if err != nil {
		return nil, err
	}

	if headerLen != 0x2020 {
		return nil, fmt.Errorf("cia: header length must be %d, got %d", 0x2020, headerLen)
	}

	var certsLen uint32
	err = binary.Read(bytes.NewReader(header[0x8:]), binary.LittleEndian, &certsLen)
	if err != nil {
		return nil, err
	}

	var ticketLen uint32
	err = binary.Read(bytes.NewReader(header[0xc:]), binary.LittleEndian, &ticketLen)
	if err != nil {
		return nil, err
	}

	var tmdLen uint32
	err = binary.Read(bytes.NewReader(header[0x10:]), binary.LittleEndian, &tmdLen)
	if err != nil {
		return nil, err
	}

	expectedCertsLen := uint32(len(Certs.Retail.CA.Raw) + len(Certs.Retail.Ticket.Raw) + len(Certs.Retail.TMD.Raw))
	if certsLen != expectedCertsLen {
		return nil, fmt.Errorf("cia: certs length must be %d, got %d", expectedCertsLen, certsLen)
	}

	err = inputReader.Discard((0x40 - (inputReader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, err
	}

	certs := make([]byte, certsLen)
	_, err = io.ReadFull(inputReader, certs)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	ticketInfo, err := CheckTicket(io.LimitReader(inputReader, int64(ticketLen)))
	if err != nil {
		return nil, err
	}

	if ticketInfo.CertsTrailer {
		return nil, fmt.Errorf("cia: unexpected certs trailer in ticket")
	}

	err = inputReader.Discard((0x40 - (inputReader.Offset() % 0x40)) % 0x40)
	if err != nil {
		return nil, err
	}

	tmdInfo, err := CheckTMD(io.LimitReader(inputReader, int64(tmdLen)))
	if err != nil {
		return nil, err
	}

	if tmdInfo.CertsTrailer {
		return nil, fmt.Errorf("cia: unexpected certs trailer in TMD")
	}

	legit := ticketInfo.Legit && tmdInfo.Legit && ticketInfo.TitleID == tmdInfo.TitleID

	return &CIAInfo{
		Legit:  legit,
		Ticket: *ticketInfo,
		TMD:    *tmdInfo,
	}, nil
}
