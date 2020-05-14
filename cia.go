package ctrsigcheck

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type CIAInfo struct {
	Legit  bool
	Ticket TicketInfo
	TMD    TMDInfo
}

func CheckCIA(cia io.ReaderAt) (*CIAInfo, error) {
	var headerLen uint32
	err := binaryReadAt(cia, 0, binary.LittleEndian, &headerLen)
	if err != nil {
		return nil, err
	}

	if headerLen != 0x2020 {
		return nil, fmt.Errorf("cia: header length must be %d, got %d", 0x2020, headerLen)
	}

	header := make([]byte, headerLen)
	_, err = cia.ReadAt(header, 0)
	if err != nil {
		return nil, err
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

	certsOffset := ((int64(headerLen) + 0x39) / 0x40) * 0x40
	ticketOffset := ((int64(certsOffset) + int64(certsLen) + 0x39) / 0x40) * 0x40
	tmdOffset := ((int64(ticketOffset) + int64(ticketLen) + 0x39) / 0x40) * 0x40

	expectedCertsLen := uint32(len(Certs.Retail.CA.Raw) + len(Certs.Retail.Ticket.Raw) + len(Certs.Retail.TMD.Raw))
	if certsLen != expectedCertsLen {
		return nil, fmt.Errorf("cia: certs length must be %d, got %d", expectedCertsLen, certsLen)
	}

	certs := make([]byte, certsLen)
	_, err = cia.ReadAt(certs, certsOffset)
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

	ticketInfo, err := CheckTicket(io.NewSectionReader(cia, ticketOffset, int64(ticketLen)), ticketLen)
	if err != nil {
		return nil, err
	}

	if ticketInfo.CertsTrailer {
		return nil, fmt.Errorf("cia: unexpected certs trailer in ticket")
	}

	tmdInfo, err := CheckTMD(io.NewSectionReader(cia, tmdOffset, int64(tmdLen)), tmdLen)
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
