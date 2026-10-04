package axpath

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	helloSize      = 64
	helloHeaderLen = 48

	helloMagic   = "AXP2"
	helloVersion = 2

	flagRoleClient = 1 << 0
	flagHasPSK     = 1 << 1
)

const (
	frameTypeData  = 0x01
	frameTypeAck   = 0x02
	frameTypePing  = 0x03
	frameTypePong  = 0x04
	frameTypeClose = 0x05
)

const (
	// DATA frame header:
	// type(1) flags(1) dsn(8) len(4)
	dataFrameHeaderLen = 1 + 1 + 8 + 4
)

type hello struct {
	Flags       byte
	SubflowID   byte
	Subflows    byte
	SessionID   [16]byte
	Epoch       uint32
	ChunkSize   uint32
	AckMaskBits uint16
}

func (h hello) isClient() bool { return (h.Flags & flagRoleClient) != 0 }

func (h hello) hasPSK() bool { return (h.Flags & flagHasPSK) != 0 }

func encodeHello(h hello, psk string) ([]byte, error) {
	var b [helloSize]byte
	copy(b[0:4], []byte(helloMagic))
	b[4] = helloVersion
	b[5] = h.Flags
	b[6] = h.SubflowID
	b[7] = h.Subflows
	copy(b[8:24], h.SessionID[:])
	binary.BigEndian.PutUint32(b[24:28], h.Epoch)
	binary.BigEndian.PutUint32(b[28:32], h.ChunkSize)
	binary.BigEndian.PutUint16(b[32:34], h.AckMaskBits)
	// b[34:48] reserved

	if psk != "" {
		mac := hmac.New(sha256.New, []byte(psk))
		_, _ = mac.Write(b[:helloHeaderLen])
		sum := mac.Sum(nil)
		copy(b[helloHeaderLen:helloSize], sum[:16])
	}
	return b[:], nil
}

func decodeHello(r io.Reader, psk string) (hello, error) {
	var b [helloSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return hello{}, err
	}
	if string(b[0:4]) != helloMagic {
		return hello{}, errors.New("axpath: bad hello magic")
	}
	if b[4] != helloVersion {
		return hello{}, errors.New("axpath: unsupported hello version")
	}

	h := hello{
		Flags:     b[5],
		SubflowID: b[6],
		Subflows:  b[7],
		Epoch:     binary.BigEndian.Uint32(b[24:28]),
		ChunkSize: binary.BigEndian.Uint32(b[28:32]),
	}
	copy(h.SessionID[:], b[8:24])
	h.AckMaskBits = binary.BigEndian.Uint16(b[32:34])

	if psk == "" {
		if h.hasPSK() {
			return hello{}, errors.New("axpath: psk mismatch (peer requires psk)")
		}
		return h, nil
	}
	if !h.hasPSK() {
		return hello{}, errors.New("axpath: psk mismatch (psk required)")
	}

	mac := hmac.New(sha256.New, []byte(psk))
	_, _ = mac.Write(b[:helloHeaderLen])
	sum := mac.Sum(nil)
	if !hmac.Equal(b[helloHeaderLen:helloSize], sum[:16]) {
		return hello{}, errors.New("axpath: bad hello auth tag")
	}
	return h, nil
}

type sackBlock struct {
	Start uint64
	End   uint64 // exclusive
}

func encodeAckFrameInto(dst []byte, dataAck uint64, blocks []sackBlock) []byte {
	if len(blocks) > 255 {
		blocks = blocks[:255]
	}
	n := 1 + 8 + 1 + (16 * len(blocks))
	if cap(dst) < n {
		dst = make([]byte, n)
	} else {
		dst = dst[:n]
	}

	dst[0] = frameTypeAck
	binary.BigEndian.PutUint64(dst[1:9], dataAck)
	dst[9] = byte(len(blocks))
	off := 10
	for _, b := range blocks {
		binary.BigEndian.PutUint64(dst[off:off+8], b.Start)
		binary.BigEndian.PutUint64(dst[off+8:off+16], b.End)
		off += 16
	}
	return dst
}

func readAckFrameInto(r io.Reader, maxBlocks int, dst []sackBlock) (dataAck uint64, blocks []sackBlock, err error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	dataAck = binary.BigEndian.Uint64(hdr[0:8])
	n := int(hdr[8])
	if maxBlocks > 0 && n > maxBlocks {
		return 0, nil, errors.New("axpath: ack has too many sack blocks")
	}
	if n <= 0 {
		return dataAck, dst[:0], nil
	}

	if cap(dst) < n {
		dst = make([]sackBlock, n)
	} else {
		dst = dst[:n]
	}

	// Fast-path: the max SACK blocks is capped (<=64), so we can read the entire
	// block payload in one ReadFull and decode from a stack buffer.
	if n <= 64 {
		var raw [16 * 64]byte
		b := raw[:16*n]
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, nil, err
		}
		for i := 0; i < n; i++ {
			off := i * 16
			dst[i] = sackBlock{
				Start: binary.BigEndian.Uint64(b[off : off+8]),
				End:   binary.BigEndian.Uint64(b[off+8 : off+16]),
			}
		}
		return dataAck, dst, nil
	}

	// Fallback for unexpected large n (should not happen with current caps).
	var one [16]byte
	for i := 0; i < n; i++ {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return 0, nil, err
		}
		dst[i] = sackBlock{
			Start: binary.BigEndian.Uint64(one[0:8]),
			End:   binary.BigEndian.Uint64(one[8:16]),
		}
	}
	return dataAck, dst, nil
}

func readAckFrame(r io.Reader, maxBlocks int) (dataAck uint64, blocks []sackBlock, err error) {
	return readAckFrameInto(r, maxBlocks, nil)
}
