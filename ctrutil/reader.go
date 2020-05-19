package ctrutil

import (
	"io"
	"io/ioutil"
)

// Reader wraps another Reader to add some capabilities.
type Reader struct {
	inner  io.Reader
	offset int64
	err    error
}

var _ io.Reader = &Reader{}

// NewReader wraps the given Reader to add some capabilities.
func NewReader(inner io.Reader) *Reader {
	if inner, ok := inner.(*Reader); ok && inner.offset == 0 {
		return inner
	}

	return &Reader{
		inner:  inner,
		offset: 0,
		err:    nil,
	}
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	n, err := r.inner.Read(p)
	r.offset += int64(n)
	r.err = err
	return n, err
}

// Offset of the next byte to be read.
func (r *Reader) Offset() int64 {
	return r.offset
}

// Err that has been returned by the last Read.
func (r *Reader) Err() error {
	return r.err
}

// Discard the next n bytes.
//
// Returns ErrUnexpectedEOF is EOF has been reached prematurely.
func (r *Reader) Discard(n int64) error {
	discarded, err := io.CopyN(ioutil.Discard, r, n)
	if err == io.EOF && discarded > 0 {
		err = io.ErrUnexpectedEOF
	}
	return err
}
