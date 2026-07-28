package cryptobox

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	serializedEnvelopeMagic   = "OWEN"
	serializedEnvelopeVersion = byte(1)
	maxSerializedEnvelopeSize = 64 * 1024
)

var ErrEnvelopeFormat = errors.New("invalid envelope encoding")

func MarshalEnvelope(env Envelope) ([]byte, error) {
	if len(env.Ciphertext) < chacha20poly1305.Overhead ||
		len(env.WrappedDataKey) != chacha20poly1305.KeySize+chacha20poly1305.Overhead {
		return nil, ErrEnvelopeFormat
	}
	size := len(serializedEnvelopeMagic) + 1 +
		4 + len(env.Ciphertext) +
		4 + len(env.Nonce) +
		4 + len(env.WrappedDataKey) +
		4 + len(env.WrapNonce)
	if size > maxSerializedEnvelopeSize {
		return nil, ErrEnvelopeFormat
	}
	encoded := make([]byte, 0, size)
	encoded = append(encoded, serializedEnvelopeMagic...)
	encoded = append(encoded, serializedEnvelopeVersion)
	encoded = appendField(encoded, env.Ciphertext)
	encoded = appendField(encoded, env.Nonce[:])
	encoded = appendField(encoded, env.WrappedDataKey)
	encoded = appendField(encoded, env.WrapNonce[:])
	return encoded, nil
}

func UnmarshalEnvelope(encoded []byte) (Envelope, error) {
	if len(encoded) > maxSerializedEnvelopeSize ||
		len(encoded) < len(serializedEnvelopeMagic)+1 ||
		!bytes.Equal(encoded[:len(serializedEnvelopeMagic)], []byte(serializedEnvelopeMagic)) ||
		encoded[len(serializedEnvelopeMagic)] != serializedEnvelopeVersion {
		return Envelope{}, ErrEnvelopeFormat
	}
	cursor := len(serializedEnvelopeMagic) + 1
	ciphertext, next, ok := readField(encoded, cursor)
	if !ok {
		return Envelope{}, ErrEnvelopeFormat
	}
	nonce, next, ok := readField(encoded, next)
	if !ok {
		return Envelope{}, ErrEnvelopeFormat
	}
	wrapped, next, ok := readField(encoded, next)
	if !ok {
		return Envelope{}, ErrEnvelopeFormat
	}
	wrapNonce, next, ok := readField(encoded, next)
	if !ok || next != len(encoded) ||
		len(ciphertext) < chacha20poly1305.Overhead ||
		len(nonce) != chacha20poly1305.NonceSizeX ||
		len(wrapped) != chacha20poly1305.KeySize+chacha20poly1305.Overhead ||
		len(wrapNonce) != chacha20poly1305.NonceSizeX {
		return Envelope{}, ErrEnvelopeFormat
	}
	var env Envelope
	env.Ciphertext = bytes.Clone(ciphertext)
	copy(env.Nonce[:], nonce)
	env.WrappedDataKey = bytes.Clone(wrapped)
	copy(env.WrapNonce[:], wrapNonce)
	return env, nil
}

func appendField(dst, field []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(field)))
	return append(dst, field...)
}

func readField(encoded []byte, offset int) ([]byte, int, bool) {
	if offset < 0 || len(encoded)-offset < 4 {
		return nil, offset, false
	}
	length := uint64(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if length > uint64(len(encoded)-offset) {
		return nil, offset, false
	}
	next := offset + int(length)
	return encoded[offset:next], next, true
}
