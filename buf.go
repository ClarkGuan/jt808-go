package jt808

import (
	"bytes"
	"errors"
	"io"
)

var ErrBuffer = errors.New("empty buffer")

type Buffer struct {
	inner [][]byte
}

func NewBuffer(total int) *Buffer {
	if total < 1 {
		panic(ErrBuffer)
	}
	return &Buffer{make([][]byte, total)}
}

func (b *Buffer) Ready() bool {
	for _, b := range b.inner {
		if len(b) == 0 {
			return false
		}
	}
	return true
}

func (b *Buffer) Len() int {
	i := 0
	for _, b := range b.inner {
		i += len(b)
	}
	return i
}

func (b *Buffer) Reader() io.Reader {
	if len(b.inner) == 1 {
		return bytes.NewReader(b.inner[0])
	}

	readers := make([]io.Reader, 0, len(b.inner))
	for _, b := range b.inner {
		readers = append(readers, bytes.NewReader(b))
	}
	return io.MultiReader(readers...)
}

func (b *Buffer) String() string {
	return string(b.Bytes())
}

func (b *Buffer) Bytes() []byte {
	ret := make([]byte, b.Len())
	buf := ret
	for _, b := range b.inner {
		n := copy(buf, b)
		buf = buf[n:]
	}
	return ret
}
