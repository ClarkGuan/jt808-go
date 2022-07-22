package jt808

import (
	"io"
	"net"
)

const (
	maxBodyLength = 1023
)

type Payload interface {
	Id() uint16
	RSA() bool
	Phone() string
	Reader() io.Reader
	Len() int
}

type Client struct {
	conn    net.Conn
	packets map[uint16]*Buffer
	sn      uint16
	buf     [1040]byte
}

func NewClient(conn net.Conn) *Client {
	c := new(Client)
	c.conn = conn
	c.packets = make(map[uint16]*Buffer)
	return c
}

func (c *Client) Send(payload Payload) error {
	size := payload.Len()
	r := size % maxBodyLength
	n := size / maxBodyLength
	if r != 0 {
		n++
	}

	header := new(Header)
	header.Id = payload.Id()
	header.SetRSA(payload.RSA())
	if err := header.SetPhone(payload.Phone()); err != nil {
		return err
	}
	header.Split(n > 1)
	reader := payload.Reader()

	for i := 0; i < n; i++ {
		size := maxBodyLength
		if i == n-1 {
			size = r
			header.SetLength(uint16(size))
		} else {
			header.SetLength(maxBodyLength)
		}
		if n > 1 {
			header.Total = uint16(n)
			header.Index = uint16(i + 1)
		}
		header.Sn = c.sn

		if err := header.Verify(); err != nil {
			return err
		}

		buf := c.buf[:]
		n, err := header.Encode(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
		if _, err := io.ReadFull(reader, buf[:size]); err != nil {
			return err
		}
		buf = buf[size:]
		buf[0] = CheckSum(c.buf[0 : cap(buf)-len(buf)])
		buf = buf[1:]
		if _, err := c.conn.Write(c.buf[0 : cap(buf)-len(buf)]); err != nil {
			return err
		}

		c.sn++
	}

	return nil
}
