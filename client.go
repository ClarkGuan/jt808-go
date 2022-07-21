package jt808

import (
	"encoding/binary"
	"io"
)

const (
	max        = uint32(1023)
	maskCipher = uint16(0b_111)
)

var (
	flag    = []byte{0x7e}
	escape1 = []byte{0x7d, 0x02}
	escape2 = []byte{0x7d, 0x01}
)

// Message 可以复用的消息体
type Message struct {
	io.Reader
	Id     uint16
	Cipher uint16
	Total  uint32
	Phone  [12]byte
}

// SetPhone 设置 Message 中的 Phone 字段
//
// ```
// var msg Message = ...
// msg.SetPhone("13000000000")
// ```
//
func (m *Message) SetPhone(s string) {
	buf := m.Phone[:]
	if len(s) < 12 {
		n := 12 - len(s)
		for i := 0; i < n; i++ {
			buf[i] = 0
		}
		copy(buf[n:], s)
	} else {
		copy(buf, s[:12])
	}
}

type Client struct {
	*Message

	offset   int
	sent     uint32
	checksum byte
	buf      [1039]byte

	// 流水号
	sn uint16
	w  io.Writer
}

func NewClient(w io.Writer) *Client {
	return &Client{w: w}
}

func (c *Client) Write(msg *Message) error {
	if msg == nil {
		return nil
	}
	c.Message = msg
	c.sent = 0
	for c.sent < c.Total {
		if err := c.writePacket(msg.Reader, c.w); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) fillHeader() {
	properties := uint16(0)
	c.offset = 0

	// Id
	binary.BigEndian.PutUint16(c.buf[c.offset:], c.Id)
	c.offset += 2
	// size
	remain := c.Total - c.sent
	if remain > max {
		properties |= uint16(max)
	} else {
		properties |= uint16(remain)
	}
	// Cipher
	properties |= (c.Cipher & maskCipher) << 10
	// subPackage
	if c.Total > max {
		properties |= uint16(1) << 13
	}
	// properties
	binary.BigEndian.PutUint16(c.buf[c.offset:], properties)
	c.offset += 2
	// Phone
	for i := 0; i < 6; i++ {
		c.buf[c.offset] = (c.Phone[2*i]-'0')<<4 | (c.Phone[2*i+1] - '0')
		c.offset++
	}
	// sn
	binary.BigEndian.PutUint16(c.buf[c.offset:], c.sn)
	c.offset += 2
	c.sn++
	// subpackage Total
	r := c.Total%max != 0
	n := c.Total / max
	if r {
		n++
	}
	binary.BigEndian.PutUint16(c.buf[c.offset:], uint16(n))
	c.offset += 2
	// order（从 1 开始）
	binary.BigEndian.PutUint16(c.buf[c.offset:], uint16(c.sent/max+1))
	c.offset += 2

	// checksum
	c.checksum = 0
	for _, b := range c.buf[:c.offset] {
		c.checksum ^= b
	}
}

func (c *Client) fillBody(r io.Reader) error {
	n := int(max)
	remain := c.Total - c.sent
	if remain <= max {
		n = int(remain)
	}
	if _, err := io.ReadFull(r, c.buf[c.offset:c.offset+n]); err != nil {
		return err
	}
	// checksum
	for _, b := range c.buf[c.offset : c.offset+n] {
		c.checksum ^= b
	}
	c.offset += n
	c.buf[c.offset] = c.checksum
	c.offset++
	return nil
}

func (c *Client) writePacket(r io.Reader, w io.Writer) error {
	if _, err := writeFull(w, flag); err != nil {
		return err
	}

	c.fillHeader()
	if err := c.fillBody(r); err != nil {
		return err
	}

	buf := c.buf[:c.offset]
	for len(buf) > 0 {
		i := -1
		var found byte
	outer:
		for j, b := range buf {
			switch b {
			case 0x7e, 0x7d:
				i = j
				found = b
				break outer
			}
		}

		if i != -1 {
			n, err := writeFull(w, buf[:i])
			c.sent += uint32(n)
			if err != nil {
				return err
			}
			// skip
			buf = buf[i+1:]
			switch found {
			case 0x7e:
				n, err = writeFull(w, escape1)
				c.sent++
				if err != nil {
					return err
				}
			case 0x7d:
				n, err = writeFull(w, escape2)
				c.sent++
				if err != nil {
					return err
				}
			}
		} else {
			n, err := writeFull(w, buf)
			c.sent += uint32(n)
			if err != nil {
				return err
			}
			break
		}
	}

	if _, err := writeFull(w, flag); err != nil {
		return err
	}

	return nil
}

func writeFull(w io.Writer, buf []byte) (int, error) {
	m := 0
	for len(buf) > 0 {
		n, err := w.Write(buf)
		m += n
		if err != nil {
			return m, err
		}
		buf = buf[n:]
	}
	return m, nil
}
