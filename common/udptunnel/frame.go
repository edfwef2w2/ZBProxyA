package udptunnel

import (
	"encoding/binary"
	"errors"
)

var (
	ErrBadMagic   = errors.New("udptunnel: bad magic")
	ErrBadVersion = errors.New("udptunnel: bad version")
	ErrTooShort   = errors.New("udptunnel: frame too short")
	ErrTooLong    = errors.New("udptunnel: payload too long")
)

// Frame is a single tunnel datagram.
type Frame struct {
	Type      uint8
	SessionID uint64
	Seq       uint32
	Ack       uint32
	Payload   []byte
}

// Encode writes f into dst (reused buffer). Returns the slice to send.
func Encode(dst []byte, f *Frame) ([]byte, error) {
	if len(f.Payload) > MaxPayload {
		return nil, ErrTooLong
	}
	need := HeaderSize + len(f.Payload)
	if cap(dst) < need {
		dst = make([]byte, need)
	} else {
		dst = dst[:need]
	}
	binary.LittleEndian.PutUint16(dst[0:2], Magic)
	dst[2] = Version
	dst[3] = f.Type
	binary.LittleEndian.PutUint64(dst[4:12], f.SessionID)
	binary.LittleEndian.PutUint32(dst[12:16], f.Seq)
	binary.LittleEndian.PutUint32(dst[16:20], f.Ack)
	binary.LittleEndian.PutUint16(dst[20:22], uint16(len(f.Payload)))
	if len(f.Payload) > 0 {
		copy(dst[22:], f.Payload)
	}
	return dst, nil
}

// Decode parses a datagram into f. Payload shares the input buffer; copy if retained.
func Decode(b []byte, f *Frame) error {
	if len(b) < HeaderSize {
		return ErrTooShort
	}
	if binary.LittleEndian.Uint16(b[0:2]) != Magic {
		return ErrBadMagic
	}
	if b[2] != Version {
		return ErrBadVersion
	}
	plen := int(binary.LittleEndian.Uint16(b[20:22]))
	if plen > MaxPayload {
		return ErrTooLong
	}
	if len(b) < HeaderSize+plen {
		return ErrTooShort
	}
	f.Type = b[3]
	f.SessionID = binary.LittleEndian.Uint64(b[4:12])
	f.Seq = binary.LittleEndian.Uint32(b[12:16])
	f.Ack = binary.LittleEndian.Uint32(b[16:20])
	if plen == 0 {
		f.Payload = nil
	} else {
		f.Payload = b[22 : 22+plen]
	}
	return nil
}

// EncodeAlloc is a convenience that allocates a fresh buffer.
func EncodeAlloc(f *Frame) ([]byte, error) {
	return Encode(nil, f)
}
