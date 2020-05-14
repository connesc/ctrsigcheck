package ctrsigcheck

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/connesc/ctrsigcheck/internal/bindata"
)

type Certificate struct {
	Name      string
	PublicKey rsa.PublicKey
	Raw       []byte
}

type CertificateSet struct {
	CA, Ticket, TMD Certificate
}

var Certs struct {
	Retail CertificateSet
	Debug  CertificateSet
}

func init() {
	certs := bindata.MustAsset("certs.bin")
	Certs.Debug.CA = parseCertificate(certs[0x10:0x410])
	Certs.Debug.Ticket = parseCertificate(certs[0x410:0x710])
	Certs.Debug.TMD = parseCertificate(certs[0x710:0xa10])
	Certs.Retail.CA = parseCertificate(certs[0xa10:0xe10])
	Certs.Retail.TMD = parseCertificate(certs[0xe10:0x1110])
	Certs.Retail.Ticket = parseCertificate(certs[0x1110:0x1410])
}

func parseCertificate(raw []byte) Certificate {
	reader := bytes.NewReader(raw)

	var signatureType uint32
	err := binaryReadAt(reader, 0, binary.BigEndian, &signatureType)
	if err != nil {
		panic(fmt.Errorf("certs: %w", err))
	}

	var signatureLen int64
	switch signatureType {
	case 0x10003:
		signatureLen = 0x240
	case 0x10004:
		signatureLen = 0x140
	default:
		panic(fmt.Errorf("certs: unexpected signature type: 0x%08x", signatureType))
	}

	var keyType uint32
	err = binaryReadAt(reader, signatureLen+0x40, binary.BigEndian, &keyType)
	if err != nil {
		panic(fmt.Errorf("certs: failed to parse key type: %w", err))
	}

	var modulusLen int64
	switch keyType {
	case 0x0:
		modulusLen = 0x200
	case 0x1:
		modulusLen = 0x100
	default:
		panic(fmt.Errorf("certs: unexpected key type: 0x%08x", keyType))
	}

	name := string(bytes.TrimRight(raw[signatureLen+0x44:signatureLen+0x84], "\x00"))

	modulus := new(big.Int).SetBytes(raw[signatureLen+0x88 : signatureLen+0x88+modulusLen])

	var exponent int32
	err = binaryReadAt(reader, signatureLen+0x88+modulusLen, binary.BigEndian, &exponent)
	if err != nil {
		panic(fmt.Errorf("certs: failed to parse public key exponent: %w", err))
	}

	return Certificate{
		Name: name,
		PublicKey: rsa.PublicKey{
			N: modulus,
			E: int(exponent),
		},
		Raw: raw,
	}
}
