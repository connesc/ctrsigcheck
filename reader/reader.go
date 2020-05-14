package reader

import (
	"io"
	"io/ioutil"
)

type Reader struct {
	inner  io.Reader
	offset int64
	err    error
}

var _ io.Reader = &Reader{}

func New(inner io.Reader) *Reader {
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

func (r *Reader) Offset() int64 {
	return r.offset
}

func (r *Reader) Err() error {
	return r.err
}

func (r *Reader) Discard(n int64) error {
	discarded, err := io.CopyN(ioutil.Discard, r, n)
	if err == io.EOF && discarded > 0 {
		err = io.ErrUnexpectedEOF
	}
	return err
}
