package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"opswarden/internal/cryptobox"
	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

const (
	argonMemory       = 64 * 1024
	argonIterations   = 3
	argonParallelism  = 2
	argonSaltLength   = 16
	argonOutputLength = 32

	loginTOTPPurpose = "login-totp"
)

type loginChallengeState struct {
	userID               string
	expiresAt            time.Time
	passwordHash         []byte
	upgradedPasswordHash []byte
}

type Service struct {
	repository    repository
	box           *cryptobox.Box
	clock         platform.Clock
	internalCIDRs []netip.Prefix
	dummyHash     []byte

	challengesMu sync.Mutex
	challenges   map[string]loginChallengeState
}

func NewService(
	db *storage.DB,
	box *cryptobox.Box,
	clock platform.Clock,
	config Config,
) (*Service, error) {
	if db == nil || db.Writer == nil || db.Reader == nil {
		return nil, errors.New("identity database is required")
	}
	if box == nil {
		return nil, errors.New("identity cryptobox is required")
	}
	if clock == nil {
		return nil, errors.New("identity clock is required")
	}
	dummyHash, err := hashPassword("opswarden-dummy-password")
	if err != nil {
		return nil, err
	}
	return &Service{
		repository:    repository{db: db},
		box:           box,
		clock:         clock,
		internalCIDRs: append([]netip.Prefix(nil), config.InternalCIDRs...),
		dummyHash:     dummyHash,
		challenges:    make(map[string]loginChallengeState),
	}, nil
}

func (s *Service) CreateInitialOwner(
	ctx context.Context,
	input CreateOwnerInput,
) (CreateOwnerResult, error) {
	if !s.initialOwnerSourceAllowed(input.SourceIP) {
		return CreateOwnerResult{}, ErrInitialOwnerSourceDenied
	}
	email := strings.TrimSpace(input.Email)
	normalizedEmail := normalizeEmail(email)
	seed, err := decodeTOTPSecret(input.TOTPSeed)
	if normalizedEmail == "" || input.Password == "" || err != nil || len(seed) == 0 {
		clear(seed)
		return CreateOwnerResult{}, ErrInvalidOwnerInput
	}
	clear(seed)

	userID, err := randomID(16)
	if err != nil {
		return CreateOwnerResult{}, err
	}
	passwordHash, err := hashPassword(input.Password)
	if err != nil {
		return CreateOwnerResult{}, err
	}
	plaintextSeed := []byte(normalizeTOTPSecret(input.TOTPSeed))
	defer clear(plaintextSeed)
	envelope, err := s.box.EncryptIdentity(
		cryptobox.IdentityContext{UserID: userID, Purpose: loginTOTPPurpose},
		plaintextSeed,
	)
	if err != nil {
		return CreateOwnerResult{}, fmt.Errorf("encrypt identity TOTP: %w", err)
	}
	encryptedTOTP, err := cryptobox.MarshalEnvelope(envelope)
	if err != nil {
		return CreateOwnerResult{}, fmt.Errorf("encode identity TOTP envelope: %w", err)
	}

	recoveryCodes := make([]string, 0, RecoveryCodeCount)
	recoveryRecords := make([]recoveryCodeRecord, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		code, err := generateRecoveryCode()
		if err != nil {
			return CreateOwnerResult{}, err
		}
		id, err := randomID(16)
		if err != nil {
			return CreateOwnerResult{}, err
		}
		sum := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
		recoveryCodes = append(recoveryCodes, code)
		recoveryRecords = append(recoveryRecords, recoveryCodeRecord{ID: id, Hash: sum[:]})
	}
	now := s.now()
	if err := s.repository.createInitialOwner(
		ctx, userID, email, normalizedEmail, passwordHash, encryptedTOTP,
		recoveryRecords, now,
	); err != nil {
		return CreateOwnerResult{}, err
	}
	return CreateOwnerResult{UserID: userID, RecoveryCodes: recoveryCodes}, nil
}

func (s *Service) BeginLogin(
	ctx context.Context,
	email, password string,
) (LoginChallenge, error) {
	record, findErr := s.repository.findUserByNormalizedEmail(ctx, normalizeEmail(email))
	hash := s.dummyHash
	if findErr == nil {
		hash = record.PasswordHash
	} else if !errors.Is(findErr, ErrUserNotFound) {
		return LoginChallenge{}, findErr
	}
	valid, paramsCurrent := verifyPassword(hash, password)
	if findErr != nil || !valid {
		return LoginChallenge{}, ErrInvalidCredentials
	}

	var upgraded []byte
	var err error
	if !paramsCurrent {
		upgraded, err = hashPassword(password)
		if err != nil {
			return LoginChallenge{}, err
		}
	}
	challengeID, err := randomID(32)
	if err != nil {
		return LoginChallenge{}, err
	}
	expiresAt := s.now().Add(LoginChallengeLifetime)
	s.challengesMu.Lock()
	s.removeExpiredChallengesLocked(s.now())
	s.challenges[challengeID] = loginChallengeState{
		userID: record.ID, expiresAt: expiresAt,
		passwordHash:         append([]byte(nil), record.PasswordHash...),
		upgradedPasswordHash: upgraded,
	}
	s.challengesMu.Unlock()
	return LoginChallenge{ID: challengeID, ExpiresAt: expiresAt}, nil
}

func (s *Service) CompleteLogin(
	ctx context.Context,
	challengeID, secondFactor string,
) (Session, error) {
	challenge, ok := s.consumeChallenge(challengeID)
	if !ok {
		return Session{}, ErrInvalidChallenge
	}
	now := s.now()
	if !now.Before(challenge.expiresAt) {
		return Session{}, ErrInvalidChallenge
	}
	rawToken, err := randomID(32)
	if err != nil {
		return Session{}, err
	}
	sessionID, err := randomID(16)
	if err != nil {
		return Session{}, err
	}
	tokenHash := sha256.Sum256([]byte(rawToken))
	expiresAt := now.Add(SessionAbsoluteLifetime)
	idleExpiresAt := now.Add(SessionIdleLifetime)
	usedTOTP := isTOTPCode(secondFactor)

	verify := func(tx *sql.Tx, encodedSecret []byte, lastCounter sql.NullInt64) error {
		if usedTOTP {
			return s.verifyAndConsumeTOTP(
				ctx, tx, challenge.userID, encodedSecret, lastCounter, secondFactor, now,
			)
		}
		sum := sha256.Sum256([]byte(normalizeRecoveryCode(secondFactor)))
		return consumeRecoveryCode(ctx, tx, challenge.userID, sum[:], now)
	}
	if err := s.repository.completeLogin(
		ctx, challenge.userID, challenge.passwordHash, now, verify, sessionID, tokenHash[:],
		expiresAt, idleExpiresAt, usedTOTP, challenge.upgradedPasswordHash,
	); err != nil {
		return Session{}, err
	}
	return Session{
		RawToken: rawToken, ExpiresAt: expiresAt, IdleExpiresAt: idleExpiresAt,
	}, nil
}

func (s *Service) ResolveSession(
	ctx context.Context,
	rawToken string,
) (SessionPrincipal, error) {
	if rawToken == "" {
		return SessionPrincipal{}, ErrInvalidSession
	}
	return s.repository.resolveSession(ctx, rawToken, s.now())
}

func (s *Service) VerifyRecentTOTP(
	ctx context.Context,
	rawToken, code string,
) (SessionPrincipal, error) {
	if rawToken == "" {
		return SessionPrincipal{}, ErrInvalidSession
	}
	if !isTOTPCode(code) {
		return SessionPrincipal{}, ErrInvalidTOTP
	}
	now := s.now()
	return s.repository.verifyRecentTOTP(
		ctx, rawToken, now,
		func(tx *sql.Tx, userID string, encodedSecret []byte, lastCounter sql.NullInt64) error {
			return s.verifyAndConsumeTOTP(
				ctx, tx, userID, encodedSecret, lastCounter, code, now,
			)
		},
	)
}

func (s *Service) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}
	return s.repository.revokeSession(ctx, rawToken, s.now())
}

func (s *Service) RevokeUserSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrUserNotFound
	}
	return s.repository.revokeUserSessions(ctx, userID, s.now())
}

func (s *Service) ResetPassword(
	ctx context.Context,
	userID, newPassword string,
) error {
	if userID == "" {
		return ErrUserNotFound
	}
	if newPassword == "" {
		return ErrInvalidCredentials
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.repository.resetPassword(ctx, userID, hash, s.now()); err != nil {
		return err
	}
	s.challengesMu.Lock()
	for id, challenge := range s.challenges {
		if challenge.userID == userID {
			delete(s.challenges, id)
		}
	}
	s.challengesMu.Unlock()
	return nil
}

func (s *Service) verifyAndConsumeTOTP(
	ctx context.Context,
	tx *sql.Tx,
	userID string,
	encodedSecret []byte,
	lastCounter sql.NullInt64,
	code string,
	now time.Time,
) error {
	envelope, err := cryptobox.UnmarshalEnvelope(encodedSecret)
	if err != nil {
		return errors.New("invalid encrypted identity TOTP")
	}
	secretText, err := s.box.DecryptIdentity(
		cryptobox.IdentityContext{UserID: userID, Purpose: loginTOTPPurpose},
		envelope,
	)
	if err != nil {
		return errors.New("decrypt identity TOTP")
	}
	defer clear(secretText)
	secret, err := decodeTOTPSecret(string(secretText))
	if err != nil {
		return errors.New("invalid encrypted identity TOTP")
	}
	defer clear(secret)

	counter, matched := matchingTOTPCounter(secret, code, now)
	if !matched {
		return ErrInvalidTOTP
	}
	if lastCounter.Valid && counter <= lastCounter.Int64 {
		return ErrTOTPReplay
	}
	return consumeTOTPCounter(ctx, tx, userID, counter, now)
}

func (s *Service) consumeChallenge(id string) (loginChallengeState, bool) {
	s.challengesMu.Lock()
	defer s.challengesMu.Unlock()
	challenge, ok := s.challenges[id]
	if ok {
		delete(s.challenges, id)
	}
	return challenge, ok
}

func (s *Service) removeExpiredChallengesLocked(now time.Time) {
	for id, challenge := range s.challenges {
		if !now.Before(challenge.expiresAt) {
			delete(s.challenges, id)
		}
	}
}

func (s *Service) initialOwnerSourceAllowed(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() {
		return false
	}
	if address.IsLoopback() {
		return true
	}
	for _, prefix := range s.internalCIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *Service) now() time.Time {
	return s.clock.Now().UTC()
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

type passwordParameters struct {
	memory       uint32
	iterations   uint32
	parallelism  uint8
	outputLength uint32
}

func hashPassword(password string) ([]byte, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	defer clear(salt)
	sum := argon2.IDKey(
		[]byte(password), salt, argonIterations, argonMemory,
		argonParallelism, argonOutputLength,
	)
	defer clear(sum)
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	)
	return []byte(encoded), nil
}

func verifyPassword(encoded []byte, password string) (valid, paramsCurrent bool) {
	params, salt, expected, ok := parsePasswordHash(encoded)
	if !ok {
		return false, false
	}
	defer clear(salt)
	defer clear(expected)
	actual := argon2.IDKey(
		[]byte(password), salt, params.iterations, params.memory,
		params.parallelism, params.outputLength,
	)
	defer clear(actual)
	valid = subtle.ConstantTimeCompare(actual, expected) == 1
	paramsCurrent = params.memory == argonMemory &&
		params.iterations == argonIterations &&
		params.parallelism == argonParallelism &&
		params.outputLength == argonOutputLength &&
		len(salt) == argonSaltLength
	return valid, paramsCurrent
}

func parsePasswordHash(encoded []byte) (passwordParameters, []byte, []byte, bool) {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" ||
		parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return passwordParameters{}, nil, nil, false
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return passwordParameters{}, nil, nil, false
	}
	memory64, ok := parseUintParameter(parameters[0], "m=", 32)
	if !ok {
		return passwordParameters{}, nil, nil, false
	}
	iterations64, ok := parseUintParameter(parameters[1], "t=", 32)
	if !ok {
		return passwordParameters{}, nil, nil, false
	}
	parallelism64, ok := parseUintParameter(parameters[2], "p=", 8)
	if !ok {
		return passwordParameters{}, nil, nil, false
	}
	memory := uint32(memory64)
	iterations := uint32(iterations64)
	parallelism := uint8(parallelism64)
	if memory < uint32(parallelism)*8 || memory > 256*1024 ||
		iterations == 0 || iterations > 10 ||
		parallelism == 0 || parallelism > 8 {
		return passwordParameters{}, nil, nil, false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		clear(salt)
		return passwordParameters{}, nil, nil, false
	}
	sum, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(sum) < 16 || len(sum) > 64 {
		clear(salt)
		clear(sum)
		return passwordParameters{}, nil, nil, false
	}
	return passwordParameters{
		memory: memory, iterations: iterations, parallelism: parallelism,
		outputLength: uint32(len(sum)),
	}, salt, sum, true
}

func parseUintParameter(value, prefix string, bitSize int) (uint64, bool) {
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value[len(prefix):], 10, bitSize)
	return parsed, err == nil
}

func normalizeTOTPSecret(secret string) string {
	return strings.TrimRight(strings.ToUpper(strings.TrimSpace(secret)), "=")
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		normalizeTOTPSecret(secret),
	)
}

func matchingTOTPCounter(secret []byte, code string, now time.Time) (int64, bool) {
	current := now.Unix() / int64(TOTPPeriod/time.Second)
	var matched int64
	found := false
	for offset := int64(-1); offset <= 1; offset++ {
		counter := current + offset
		if counter < 0 {
			continue
		}
		expected := totpCode(secret, uint64(counter))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			if !found || counter > matched {
				matched = counter
			}
			found = true
		}
	}
	return matched, found
}

func totpCode(secret []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", value)
}

func isTOTPCode(value string) bool {
	if len(value) != 6 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func generateRecoveryCode() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate recovery code: %w", err)
	}
	defer clear(raw)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return "OWRC-" + encoded[:5] + "-" + encoded[5:10] + "-" +
		encoded[10:15] + "-" + encoded[15:20] + "-" + encoded[20:], nil
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

func randomID(byteLength int) (string, error) {
	raw := make([]byte, byteLength)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate random identity value: %w", err)
	}
	defer clear(raw)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
