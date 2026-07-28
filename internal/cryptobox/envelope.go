package cryptobox

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/unix"
)

const (
	payloadDomain         = "opswarden/credential-payload/v1"
	wrapDomain            = "opswarden/data-key-wrap/v1"
	maxEncodedKeyFileSize = 1024
)

var (
	ErrAuthentication = errors.New("envelope authentication failed")
	ErrContextChange  = errors.New("credential context cannot change during data key rewrap")
	ErrKeyPermissions = errors.New("master key file permissions are too broad")
	ErrKeyFileType    = errors.New("master key path is not a regular file")
	ErrKeyFormat      = errors.New("master key must be base64 for exactly 32 bytes")
)

type CredentialContext struct {
	CredentialID string
	SpaceID      string
	Version      uint64
	Type         string
}

type Envelope struct {
	Ciphertext     []byte
	Nonce          [chacha20poly1305.NonceSizeX]byte
	WrappedDataKey []byte
	WrapNonce      [chacha20poly1305.NonceSizeX]byte
}

type Box struct {
	masterKey [chacha20poly1305.KeySize]byte
}

func New(masterKey [chacha20poly1305.KeySize]byte) *Box {
	return &Box{masterKey: masterKey}
}

func LoadMasterKey(path string) ([chacha20poly1305.KeySize]byte, error) {
	return loadMasterKey(path, nil)
}

func loadMasterKey(path string, afterLstat func() error) ([chacha20poly1305.KeySize]byte, error) {
	var key [chacha20poly1305.KeySize]byte

	pathInfo, err := os.Lstat(path)
	if err != nil {
		return key, fmt.Errorf("inspect master key file: %w", err)
	}
	if err := validateMasterKeyFileInfo(pathInfo); err != nil {
		return key, err
	}
	if afterLstat != nil {
		if err := afterLstat(); err != nil {
			return key, fmt.Errorf("run master key test hook: %w", err)
		}
	}

	file, err := openMasterKeyFile(path)
	if err != nil {
		return key, err
	}
	defer file.Close()

	openInfo, err := file.Stat()
	if err != nil {
		return key, fmt.Errorf("inspect open master key file: %w", err)
	}
	if err := validateStableMasterKeyFileInfo(pathInfo, openInfo); err != nil {
		return key, err
	}

	encoded, err := io.ReadAll(io.LimitReader(file, maxEncodedKeyFileSize+1))
	if err != nil {
		return key, fmt.Errorf("read master key file: %w", err)
	}
	defer clear(encoded)
	if len(encoded) > maxEncodedKeyFileSize {
		return key, ErrKeyFormat
	}

	afterReadInfo, err := file.Stat()
	if err != nil {
		return key, fmt.Errorf("reinspect open master key file: %w", err)
	}
	if err := validateStableMasterKeyFileInfo(openInfo, afterReadInfo); err != nil {
		return key, err
	}

	afterReadPathInfo, err := os.Lstat(path)
	if err != nil {
		return key, fmt.Errorf("reinspect master key path: %w", err)
	}
	if err := validateStableMasterKeyFileInfo(afterReadInfo, afterReadPathInfo); err != nil {
		return key, err
	}

	return decodeMasterKey(encoded)
}

func decodeMasterKey(encoded []byte) ([chacha20poly1305.KeySize]byte, error) {
	var key [chacha20poly1305.KeySize]byte
	defer clear(encoded)

	trimmed := bytes.TrimSpace(encoded)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	defer clear(decoded)
	decodedLen, err := base64.StdEncoding.Decode(decoded, trimmed)
	if err != nil || decodedLen != len(key) {
		return key, ErrKeyFormat
	}
	copy(key[:], decoded[:decodedLen])

	return key, nil
}

func openMasterKeyFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, ErrKeyFileType
		}
		return nil, fmt.Errorf("open master key file without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap master key file descriptor")
	}
	return file, nil
}

func validateMasterKeyFileInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return ErrKeyFileType
	}
	if info.Mode().Perm()&^os.FileMode(0o600) != 0 {
		return ErrKeyPermissions
	}
	return nil
}

func validateStableMasterKeyFileInfo(before, after os.FileInfo) error {
	if err := validateMasterKeyFileInfo(after); err != nil {
		return err
	}
	if !os.SameFile(before, after) {
		return ErrKeyFileType
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		return ErrKeyPermissions
	}
	return nil
}

func (b *Box) EncryptCredential(ctx CredentialContext, plaintext []byte) (Envelope, error) {
	var env Envelope
	dataKey := make([]byte, chacha20poly1305.KeySize)
	defer clear(dataKey)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return env, fmt.Errorf("generate data key: %w", err)
	}

	payloadAEAD, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return env, fmt.Errorf("create payload cipher: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, env.Nonce[:]); err != nil {
		return Envelope{}, fmt.Errorf("generate payload nonce: %w", err)
	}
	env.Ciphertext = payloadAEAD.Seal(
		nil,
		env.Nonce[:],
		plaintext,
		credentialAAD(payloadDomain, ctx),
	)

	wrappingAEAD, err := chacha20poly1305.NewX(b.masterKey[:])
	if err != nil {
		return Envelope{}, fmt.Errorf("create wrapping cipher: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, env.WrapNonce[:]); err != nil {
		return Envelope{}, fmt.Errorf("generate wrapping nonce: %w", err)
	}
	env.WrappedDataKey = wrappingAEAD.Seal(
		nil,
		env.WrapNonce[:],
		dataKey,
		credentialAAD(wrapDomain, ctx),
	)

	return env, nil
}

func (b *Box) DecryptCredential(ctx CredentialContext, env Envelope) ([]byte, error) {
	dataKey, err := b.unwrapDataKey(ctx, env)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)

	return decryptPayload(ctx, env, dataKey)
}

func (b *Box) RewrapDataKey(
	oldCtx, newCtx CredentialContext,
	env Envelope,
	newMaster [chacha20poly1305.KeySize]byte,
) (Envelope, error) {
	if oldCtx != newCtx {
		return Envelope{}, ErrContextChange
	}

	dataKey, err := b.unwrapDataKey(oldCtx, env)
	if err != nil {
		return Envelope{}, err
	}
	defer clear(dataKey)

	plaintext, err := decryptPayload(oldCtx, env, dataKey)
	if err != nil {
		return Envelope{}, err
	}
	clear(plaintext)

	wrappingAEAD, err := chacha20poly1305.NewX(newMaster[:])
	if err != nil {
		return Envelope{}, fmt.Errorf("create new wrapping cipher: %w", err)
	}
	rewrapped := Envelope{
		Ciphertext: bytes.Clone(env.Ciphertext),
		Nonce:      env.Nonce,
	}
	if _, err := io.ReadFull(rand.Reader, rewrapped.WrapNonce[:]); err != nil {
		return Envelope{}, fmt.Errorf("generate new wrapping nonce: %w", err)
	}
	rewrapped.WrappedDataKey = wrappingAEAD.Seal(
		nil,
		rewrapped.WrapNonce[:],
		dataKey,
		credentialAAD(wrapDomain, newCtx),
	)

	return rewrapped, nil
}

func (b *Box) unwrapDataKey(ctx CredentialContext, env Envelope) ([]byte, error) {
	wrappingAEAD, err := chacha20poly1305.NewX(b.masterKey[:])
	if err != nil {
		return nil, fmt.Errorf("create wrapping cipher: %w", err)
	}
	dataKey, err := wrappingAEAD.Open(
		nil,
		env.WrapNonce[:],
		env.WrappedDataKey,
		credentialAAD(wrapDomain, ctx),
	)
	if err != nil || len(dataKey) != chacha20poly1305.KeySize {
		clear(dataKey)
		return nil, ErrAuthentication
	}
	return dataKey, nil
}

func decryptPayload(ctx CredentialContext, env Envelope, dataKey []byte) ([]byte, error) {
	payloadAEAD, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, ErrAuthentication
	}
	plaintext, err := payloadAEAD.Open(
		nil,
		env.Nonce[:],
		env.Ciphertext,
		credentialAAD(payloadDomain, ctx),
	)
	if err != nil {
		clear(plaintext)
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func credentialAAD(domain string, ctx CredentialContext) []byte {
	size := len(domain) + 8 + len(ctx.CredentialID) + 8 + len(ctx.SpaceID) +
		8 + 8 + len(ctx.Type)
	aad := make([]byte, 0, size)
	aad = append(aad, domain...)
	aad = appendLengthPrefixed(aad, ctx.CredentialID)
	aad = appendLengthPrefixed(aad, ctx.SpaceID)
	aad = binary.BigEndian.AppendUint64(aad, ctx.Version)
	aad = appendLengthPrefixed(aad, ctx.Type)
	return aad
}

func appendLengthPrefixed(dst []byte, value string) []byte {
	dst = binary.BigEndian.AppendUint64(dst, uint64(len([]byte(value))))
	return append(dst, value...)
}
