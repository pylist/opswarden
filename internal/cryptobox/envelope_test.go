package cryptobox

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMasterKeyAcceptsRestrictedRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	want := bytes.Repeat([]byte{7}, 32)
	raw := base64.StdEncoding.EncodeToString(want)
	if err := os.WriteFile(path, []byte(raw+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}

	got, err := LoadMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatal("loaded master key mismatch")
	}
}

func TestLoadMasterKeyRejectsSymlinkSwapAfterLstat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	renamedPath := filepath.Join(dir, "original.key")
	raw := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	afterLstat := func() error {
		if err := os.Rename(path, renamedPath); err != nil {
			return err
		}
		return os.Symlink(renamedPath, path)
	}
	_, err := loadMasterKey(path, afterLstat)
	if !errors.Is(err, ErrKeyFileType) {
		t.Fatalf("expected key file type error, got %v", err)
	}
}

func TestLoadMasterKeyRejectsPermissionChangeAfterLstat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	raw := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := os.WriteFile(path, []byte(raw), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}

	afterLstat := func() error {
		return os.Chmod(path, 0o600)
	}
	_, err := loadMasterKey(path, afterLstat)
	if !errors.Is(err, ErrKeyPermissions) {
		t.Fatalf("expected key permissions error, got %v", err)
	}
}

func TestLoadMasterKeyRejectsGroupReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	raw := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := os.WriteFile(path, []byte(raw), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}

	_, err := LoadMasterKey(path)
	if !errors.Is(err, ErrKeyPermissions) {
		t.Fatalf("got %v", err)
	}
}

func TestMasterKeyFileInfoRejectsPermissionsThatBecomeBroad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("unused"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	err = validateMasterKeyFileInfo(info)
	if !errors.Is(err, ErrKeyPermissions) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadMasterKeyRejectsNonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := LoadMasterKey(path)
	if !errors.Is(err, ErrKeyFileType) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadMasterKeyRejectsMalformedOrWrongLengthContent(t *testing.T) {
	tests := map[string]string{
		"malformed":     "not-base64!",
		"31 byte key":   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 31)),
		"33 byte key":   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 33)),
		"trailing data": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) + " x",
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "master.key")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := LoadMasterKey(path)
			if !errors.Is(err, ErrKeyFormat) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestLoadMasterKeyRejectsContentBeyondReadLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	raw := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	oversized := raw + strings.Repeat(" ", 1025-len(raw)) + "not-base64"
	if err := os.WriteFile(path, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadMasterKey(path)
	if !errors.Is(err, ErrKeyFormat) {
		t.Fatalf("got %v", err)
	}
}

func TestDecodeMasterKeyClearsEncodedInput(t *testing.T) {
	tests := map[string][]byte{
		"success": []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))),
		"failure": []byte("not-base64"),
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			_, _ = decodeMasterKey(encoded)
			if !bytes.Equal(encoded, make([]byte, len(encoded))) {
				t.Fatal("encoded master key buffer was not cleared")
			}
		})
	}
}

func TestCredentialAADUsesDomainSeparatedCanonicalEncoding(t *testing.T) {
	ctx := CredentialContext{
		CredentialID: "c1",
		SpaceID:      "空间",
		Version:      0x0102030405060708,
		Type:         "login",
	}

	var fields bytes.Buffer
	for _, field := range []string{ctx.CredentialID, ctx.SpaceID} {
		if err := binary.Write(&fields, binary.BigEndian, uint64(len([]byte(field)))); err != nil {
			t.Fatal(err)
		}
		fields.WriteString(field)
	}
	if err := binary.Write(&fields, binary.BigEndian, ctx.Version); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&fields, binary.BigEndian, uint64(len([]byte(ctx.Type)))); err != nil {
		t.Fatal(err)
	}
	fields.WriteString(ctx.Type)

	wantPayload := append([]byte("opswarden/credential-payload/v1"), fields.Bytes()...)
	wantWrap := append([]byte("opswarden/data-key-wrap/v1"), fields.Bytes()...)
	if got := credentialAAD(payloadDomain, ctx); !bytes.Equal(got, wantPayload) {
		t.Fatal("payload AAD mismatch")
	}
	if got := credentialAAD(wrapDomain, ctx); !bytes.Equal(got, wantWrap) {
		t.Fatal("wrap AAD mismatch")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	box := newTestBox(1)
	ctx := testContext()
	plaintext := []byte(`{"password":"p"}`)

	env, err := box.EncryptCredential(ctx, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if env.Nonce == env.WrapNonce {
		t.Fatal("payload and wrapping nonces must be independently generated")
	}
	if len(env.Ciphertext) != len(plaintext)+16 {
		t.Fatalf("ciphertext length = %d", len(env.Ciphertext))
	}
	if len(env.WrappedDataKey) != 32+16 {
		t.Fatalf("wrapped data key length = %d", len(env.WrappedDataKey))
	}

	got, err := box.DecryptCredential(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted credential plaintext mismatch")
	}
}

func TestEnvelopeRejectsMovedCiphertext(t *testing.T) {
	box := newTestBox(1)
	env, err := box.EncryptCredential(testContext(), []byte(`{"password":"p"}`))
	if err != nil {
		t.Fatal(err)
	}

	contexts := map[string]CredentialContext{
		"credential ID": {CredentialID: "c2", SpaceID: "s1", Version: 1, Type: "login"},
		"space ID":      {CredentialID: "c1", SpaceID: "s2", Version: 1, Type: "login"},
		"version":       {CredentialID: "c1", SpaceID: "s1", Version: 2, Type: "login"},
		"type":          {CredentialID: "c1", SpaceID: "s1", Version: 1, Type: "note"},
	}
	for name, movedCtx := range contexts {
		t.Run(name, func(t *testing.T) {
			_, err := box.DecryptCredential(movedCtx, env)
			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestEnvelopeRejectsTampering(t *testing.T) {
	box := newTestBox(1)
	ctx := testContext()
	original, err := box.EncryptCredential(ctx, []byte(`{"password":"p"}`))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(Envelope) Envelope{
		"ciphertext": func(env Envelope) Envelope {
			env.Ciphertext = bytes.Clone(env.Ciphertext)
			env.Ciphertext[0] ^= 1
			return env
		},
		"nonce": func(env Envelope) Envelope {
			env.Nonce[0] ^= 1
			return env
		},
		"wrapped data key": func(env Envelope) Envelope {
			env.WrappedDataKey = bytes.Clone(env.WrappedDataKey)
			env.WrappedDataKey[0] ^= 1
			return env
		},
		"wrap nonce": func(env Envelope) Envelope {
			env.WrapNonce[0] ^= 1
			return env
		},
	}
	for name, alter := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := box.DecryptCredential(ctx, alter(original))
			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestRewrapDataKeyRejectsContextChange(t *testing.T) {
	box := newTestBox(1)
	ctx := testContext()
	env, err := box.EncryptCredential(ctx, []byte(`{"password":"p"}`))
	if err != nil {
		t.Fatal(err)
	}
	changed := ctx
	changed.Version++

	_, err = box.RewrapDataKey(ctx, changed, env, testMasterKey(2))
	if !errors.Is(err, ErrContextChange) {
		t.Fatalf("got %v", err)
	}
}

func TestRewrapDataKeyRotatesOnlyWrappedKey(t *testing.T) {
	oldBox := newTestBox(1)
	ctx := testContext()
	plaintext := []byte(`{"password":"p"}`)
	env, err := oldBox.EncryptCredential(ctx, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	newMaster := testMasterKey(2)
	rewrapped, err := oldBox.RewrapDataKey(ctx, ctx, env, newMaster)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rewrapped.Ciphertext, env.Ciphertext) {
		t.Fatal("rewrap changed credential ciphertext")
	}
	if rewrapped.Nonce != env.Nonce {
		t.Fatal("rewrap changed credential nonce")
	}
	if rewrapped.WrapNonce == env.WrapNonce {
		t.Fatal("rewrap reused wrapping nonce")
	}
	if bytes.Equal(rewrapped.WrappedDataKey, env.WrappedDataKey) {
		t.Fatal("rewrap did not replace wrapped data key")
	}

	if _, err := oldBox.DecryptCredential(ctx, rewrapped); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("old master key got %v", err)
	}
	newBox := New(newMaster)
	got, err := newBox.DecryptCredential(ctx, rewrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted credential plaintext mismatch after rewrap")
	}
}

func testContext() CredentialContext {
	return CredentialContext{
		CredentialID: "c1",
		SpaceID:      "s1",
		Version:      1,
		Type:         "login",
	}
}

func testMasterKey(value byte) [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = value
	}
	return key
}

func newTestBox(keyByte byte) *Box {
	return New(testMasterKey(keyByte))
}
