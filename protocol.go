package jt808

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	maxLength           = 1040
	maxLength2          = 2 * maxLength
	headerMaxLength     = 16
	headerNoSplitLength = 12
)

var (
	ErrSpace = errors.New("not enough space")
	ErrIndex = errors.New("index < 1 or index > total")
	ErrTotal = errors.New("total < 2")
	ErrPhone = errors.New("not phone number")
)

type Verifier interface {
	Verify() error
}

type Header struct {
	Id    uint16
	Sn    uint16
	Total uint16
	Index uint16

	prop  uint16
	phone [6]byte
}

func (h *Header) SetLength(length uint16) {
	h.prop |= length & 0b_11111_11111
}

func (h *Header) GetLength() uint16 {
	return h.prop & 0b_11111_11111
}

func (h *Header) SetRSA(enable bool) {
	if enable {
		h.prop |= uint16(1 << 10)
	} else {
		h.prop &= ^uint16(1 << 10)
	}
}

func (h *Header) GetRSA() bool {
	return h.prop>>10&1 != 0
}

func (h *Header) Split(yes bool) {
	if yes {
		h.prop |= uint16(1 << 13)
	} else {
		h.prop &= ^uint16(1 << 13)
	}
}

func (h *Header) GetSplit() bool {
	return h.prop>>13&1 != 0
}

func num(b byte) (byte, error) {
	ret := b - '0'
	if ret < 0 || ret > 9 {
		return 0, ErrPhone
	}
	return ret, nil
}

func (h *Header) SetPhone(phone string) error {
	size := len(phone)
	source := make([]byte, 12)
	buf := source[:]
	if size < 12 {
		buf = buf[12-size:]
	}
	copy(buf, phone)
	for i := 0; i < 6; i++ {
		high, err := num(source[i*2])
		if err != nil {
			return err
		}
		low, err := num(source[i*2+1])
		if err != nil {
			return err
		}
		h.phone[i] = high<<4 | low
	}
	return nil
}

func (h *Header) GetPhone() string {
	buf := make([]byte, 12)
	for i, b := range h.phone {
		buf[i*2] = b >> 4
		buf[i*2+1] = b & 0b_1111
	}
	index := -1
	for i := range buf {
		if buf[i] != 0 {
			index = i
			break
		}
	}
	return string(buf[index:])
}

func (h *Header) Verify() error {
	if h.GetSplit() {
		if h.Total < 2 {
			return ErrTotal
		}
		if h.Index < 1 || h.Index > h.Total {
			return ErrIndex
		}
	}
	return nil
}

func (h *Header) String() string {
	buf := new(strings.Builder)
	_, _ = fmt.Fprintf(buf, "808 header {\n")
	_, _ = fmt.Fprintf(buf, "\tid: %d\n", h.Id)
	_, _ = fmt.Fprintf(buf, "\tlength: %d\n", h.GetLength())
	_, _ = fmt.Fprintf(buf, "\tRAS: %t\n", h.GetRSA())
	_, _ = fmt.Fprintf(buf, "\tsplit: %t\n", h.GetSplit())
	_, _ = fmt.Fprintf(buf, "\tphone: %s\n", h.GetPhone())
	_, _ = fmt.Fprintf(buf, "\tsn: %d\n", h.Sn)
	if h.GetSplit() {
		_, _ = fmt.Fprintf(buf, "\ttotal: %d\n", h.Total)
		_, _ = fmt.Fprintf(buf, "\tindex: %d\n", h.Index)
	}
	_, _ = fmt.Fprintf(buf, "}\n")
	return buf.String()
}

func (h *Header) Encode(data []byte) (int, error) {
	if h.GetSplit() && len(data) < headerMaxLength || (!h.GetSplit() && len(data) < headerNoSplitLength) {
		return 0, ErrSpace
	}
	buf := data[:]
	// id
	binary.BigEndian.PutUint16(buf, h.Id)
	buf = buf[2:]
	// prop
	binary.BigEndian.PutUint16(buf, h.prop)
	buf = buf[2:]
	// phone
	copy(buf, h.phone[:])
	buf = buf[6:]
	// sn
	binary.BigEndian.PutUint16(buf, h.Sn)
	buf = buf[2:]
	// split
	if h.GetSplit() {
		binary.BigEndian.PutUint16(buf, h.Total)
		buf = buf[2:]
		binary.BigEndian.PutUint16(buf, h.Index)
		return headerMaxLength, nil
	}
	return headerNoSplitLength, nil
}

func (h *Header) Decode(data []byte) (int, error) {
	if len(data) < headerNoSplitLength {
		return 0, ErrSpace
	}
	buf := data[:]
	// id
	h.Id = binary.BigEndian.Uint16(buf)
	buf = buf[2:]
	// prop
	h.prop = binary.BigEndian.Uint16(buf)
	buf = buf[2:]
	// phone
	copy(h.phone[:], buf)
	buf = buf[6:]
	// sn
	h.Sn = binary.BigEndian.Uint16(buf)
	buf = buf[2:]
	// split
	if h.GetSplit() {
		if len(data) < headerMaxLength {
			return 0, ErrSpace
		}
		h.Total = binary.BigEndian.Uint16(buf)
		buf = buf[2:]
		h.Index = binary.BigEndian.Uint16(buf)
		return headerMaxLength, nil
	}
	return headerNoSplitLength, nil
}

func CheckSum(data []byte) byte {
	c := byte(0)
	for _, b := range data {
		c ^= b
	}
	return c
}

func Unescape(buf, data []byte) (int, error) {
	if len(buf) < maxLength {
		return 0, ErrSpace
	}

	target := data[:]
	buf = buf[:0]
	for len(target) > 0 {
		if target[0] == 0x7d {
			if len(target) > 1 {
				switch target[1] {
				case 0x01:
					buf = append(buf, 0x7d)
				case 0x02:
					buf = append(buf, 0x7e)
				default:
					buf = append(buf, target[:2]...)
				}
				target = target[2:]
				continue
			}
		}

		buf = append(buf, target[0])
		target = target[1:]
	}

	return len(buf), nil
}

func Escape(buf []byte, data []byte) (int, error) {
	if len(buf) < maxLength2 {
		return 0, ErrSpace
	}
	target := data[:]
	buf = buf[:0]
	for len(target) > 0 {
		i := -1
		found := byte(0)
	out:
		for j, b := range target {
			switch b {
			case 0x7d, 0x7e:
				i = j
				found = b
				break out
			}
		}
		if i == -1 {
			buf = append(buf, target...)
			break
		} else {
			buf = append(buf, target[:i]...)
			switch found {
			case 0x7d:
				buf = append(buf, 0x7d, 0x01)
			case 0x7e:
				buf = append(buf, 0x7d, 0x02)
			}
			target = target[i+1:]
		}
	}
	return len(buf), nil
}
