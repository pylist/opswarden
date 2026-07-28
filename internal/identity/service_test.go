package identity

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"opswarden/internal/cryptobox"
	"opswarden/internal/storage"
)

const (
	testEmail    = "Owner@Example.com"
	testPassword = "correct horse battery staple fixture"
	testTOTPSeed = "JBSWY3DPEHPK3PXP"
)

func TestCreateInitialOwnerRestrictsSourceAndPersistsApprovedArgonParameters(t *testing.T) {
	h := newIdentityHarnessWithoutOwner(t)

	_, err := h.service.CreateInitialOwner(h.ctx, CreateOwnerInput{
		Email: testEmail, Password: testPassword, TOTPSeed: testTOTPSeed,
		SourceIP: netip.MustParseAddr("203.0.113.8"),
	})
	if !errors.Is(err, ErrInitialOwnerSourceDenied) {
		t.Fatalf("public source error = %v", err)
	}

	result, err := h.service.CreateInitialOwner(h.ctx, CreateOwnerInput{
		Email: testEmail, Password: testPassword, TOTPSeed: testTOTPSeed,
		SourceIP: netip.MustParseAddr("10.23.4.5"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.UserID == "" || len(result.RecoveryCodes) != RecoveryCodeCount {
		t.Fatalf("owner result = %+v", result)
	}

	var hash []byte
	var role string
	if err := h.db.Reader.QueryRowContext(h.ctx,
		`SELECT password_hash, system_role FROM users WHERE id = ?`, result.UserID,
	).Scan(&hash, &role); err != nil {
		t.Fatal(err)
	}
	if role != SystemRoleOwner {
		t.Fatalf("system role = %q", role)
	}
	encoded := string(hash)
	for _, fragment := range []string{
		"$argon2id$v=19$", "m=65536", "t=3", "p=2",
	} {
		if !strings.Contains(encoded, fragment) {
			t.Fatalf("password hash %q missing %q", encoded, fragment)
		}
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("password hash parts = %d", len(parts))
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		t.Fatalf("salt length = %d, err = %v", len(salt), err)
	}
	sum, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(sum) != 32 {
		t.Fatalf("output length = %d, err = %v", len(sum), err)
	}

	_, err = h.service.CreateInitialOwner(h.ctx, CreateOwnerInput{
		Email: "other@example.com", Password: "another sufficiently long password",
		TOTPSeed: testTOTPSeed, SourceIP: netip.MustParseAddr("127.0.0.1"),
	})
	if !errors.Is(err, ErrInitialOwnerExists) {
		t.Fatalf("second owner error = %v", err)
	}
}

func TestBeginLoginUsesUnifiedCredentialError(t *testing.T) {
	h := newIdentityHarness(t)

	for name, credentials := range map[string][2]string{
		"unknown account": {"missing@example.com", "wrong password"},
		"wrong password":  {testEmail, "wrong password"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.service.BeginLogin(h.ctx, credentials[0], credentials[1])
			if err != ErrInvalidCredentials {
				t.Fatalf("error = %#v, want shared ErrInvalidCredentials", err)
			}
		})
	}

	challenge, err := h.service.BeginLogin(h.ctx, "  OWNER@example.COM ", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.ID == "" || !challenge.ExpiresAt.Equal(h.clock.Now().Add(LoginChallengeLifetime)) {
		t.Fatalf("challenge = %+v", challenge)
	}
}

func TestBeginLoginUsesOnlyApprovedBoundedPasswordKDFWork(t *testing.T) {
	tests := map[string]struct {
		email      string
		password   string
		storedHash func(*recordingPasswordKDF) []byte
		outputLen  uint32
	}{
		"unknown account": {
			email: "missing@example.com", password: "wrong password",
			outputLen: argonOutputLength,
		},
		"current wrong password": {
			email: testEmail, password: "wrong password",
			outputLen: argonOutputLength,
		},
		"malformed PHC": {
			email: testEmail, password: testPassword,
			storedHash: func(*recordingPasswordKDF) []byte { return []byte("not-a-phc") },
			outputLen:  argonOutputLength,
		},
		"unapproved high-cost PHC": {
			email: testEmail, password: testPassword,
			storedHash: func(*recordingPasswordKDF) []byte {
				return []byte("$argon2id$v=19$m=262144,t=10,p=8$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY")
			},
			outputLen: argonOutputLength,
		},
		"noncanonical leading zeros": {
			email: testEmail, password: testPassword,
			storedHash: func(*recordingPasswordKDF) []byte {
				return []byte("$argon2id$v=19$m=065536,t=03,p=02$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY")
			},
			outputLen: argonOutputLength,
		},
		"legacy wrong password": {
			email: testEmail, password: "wrong password",
			storedHash: func(kdf *recordingPasswordKDF) []byte {
				return testPasswordHash(
					t, kdf.derive, testPassword,
					passwordParameters{
						memory: argonMemory, iterations: argonIterations,
						parallelism: argonParallelism, outputLength: legacyArgonOutputLength,
					},
				)
			},
			outputLen: legacyArgonOutputLength,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			kdf := &recordingPasswordKDF{}
			h := newIdentityHarnessWithKDF(t, kdf.derive)
			if test.storedHash != nil {
				hash := test.storedHash(kdf)
				if _, err := h.db.Writer.ExecContext(h.ctx,
					`UPDATE users SET password_hash = ? WHERE id = ?`,
					hash, h.owner.UserID,
				); err != nil {
					t.Fatal(err)
				}
			}
			kdf.reset()

			if _, err := h.service.BeginLogin(h.ctx, test.email, test.password); err != ErrInvalidCredentials {
				t.Fatalf("error = %v", err)
			}
			if len(kdf.calls) != 1 {
				t.Fatalf("KDF calls = %+v, want exactly one", kdf.calls)
			}
			call := kdf.calls[0]
			if call.memory != argonMemory || call.iterations != argonIterations ||
				call.parallelism != argonParallelism || call.outputLength != test.outputLen ||
				call.saltLength != argonSaltLength {
				t.Fatalf("KDF call = %+v", call)
			}
		})
	}
}

func TestSuccessfulLegacyPasswordLoginUpgradesToCurrentPHC(t *testing.T) {
	kdf := &recordingPasswordKDF{}
	h := newIdentityHarnessWithKDF(t, kdf.derive)
	legacy := testPasswordHash(
		t, kdf.derive, testPassword,
		passwordParameters{
			memory: argonMemory, iterations: argonIterations,
			parallelism: argonParallelism, outputLength: legacyArgonOutputLength,
		},
	)
	if _, err := h.db.Writer.ExecContext(h.ctx,
		`UPDATE users SET password_hash = ? WHERE id = ?`, legacy, h.owner.UserID,
	); err != nil {
		t.Fatal(err)
	}
	kdf.reset()

	challenge := h.beginLogin(t, testPassword)
	if len(kdf.calls) != 2 ||
		kdf.calls[0].outputLength != legacyArgonOutputLength ||
		kdf.calls[1].outputLength != argonOutputLength {
		t.Fatalf("legacy/current KDF calls = %+v", kdf.calls)
	}
	if _, err := h.service.CompleteLogin(
		h.ctx, challenge.ID, h.totpAt(h.clock.Now()),
	); err != nil {
		t.Fatal(err)
	}
	var encoded []byte
	if err := h.db.Reader.QueryRowContext(h.ctx,
		`SELECT password_hash FROM users WHERE id = ?`, h.owner.UserID,
	).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	params, _, _, kind := parsePasswordHash(encoded)
	if kind != passwordHashCurrent || params.outputLength != argonOutputLength {
		t.Fatalf("upgraded password kind/params = %v/%+v", kind, params)
	}
}

func TestLoginRequiresOneTimeChallengeAndTOTPWithinWindow(t *testing.T) {
	h := newIdentityHarness(t)

	challenge := h.beginLogin(t, testPassword)
	if _, err := h.service.CompleteLogin(h.ctx, challenge.ID, "000000"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("wrong TOTP error = %v", err)
	}
	if _, err := h.service.CompleteLogin(h.ctx, challenge.ID, h.totpAt(h.clock.Now())); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("reused failed challenge error = %v", err)
	}

	previousWindow := h.totpAt(h.clock.Now().Add(-TOTPPeriod))
	session, err := h.service.CompleteLogin(h.ctx, h.beginLogin(t, testPassword).ID, previousWindow)
	if err != nil {
		t.Fatal(err)
	}
	if session.RawToken == "" || !session.ExpiresAt.Equal(h.clock.Now().Add(SessionAbsoluteLifetime)) ||
		!session.IdleExpiresAt.Equal(h.clock.Now().Add(SessionIdleLifetime)) {
		t.Fatalf("session = %+v", session)
	}
	raw, err := base64.RawURLEncoding.DecodeString(session.RawToken)
	if err != nil || len(raw) != 32 {
		t.Fatalf("session token bytes = %d, err = %v", len(raw), err)
	}

	if _, err := h.service.CompleteLogin(
		h.ctx, h.beginLogin(t, testPassword).ID, previousWindow,
	); !errors.Is(err, ErrTOTPReplay) {
		t.Fatalf("replayed TOTP error = %v", err)
	}

	h.clock.Advance(2 * TOTPPeriod)
	tooOld := h.totpAt(h.clock.Now().Add(-2 * TOTPPeriod))
	if _, err := h.service.CompleteLogin(
		h.ctx, h.beginLogin(t, testPassword).ID, tooOld,
	); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("out-of-window TOTP error = %v", err)
	}
}

func TestConcurrentTOTPReplayAllowsOneSession(t *testing.T) {
	h := newIdentityHarness(t)
	code := h.totpAt(h.clock.Now())
	challenges := []LoginChallenge{
		h.beginLogin(t, testPassword),
		h.beginLogin(t, testPassword),
	}

	start := make(chan struct{})
	errs := make(chan error, len(challenges))
	var ready sync.WaitGroup
	ready.Add(len(challenges))
	for _, challenge := range challenges {
		go func() {
			ready.Done()
			<-start
			_, err := h.service.CompleteLogin(h.ctx, challenge.ID, code)
			errs <- err
		}()
	}
	ready.Wait()
	close(start)

	var succeeded, replayed int
	for range challenges {
		switch err := <-errs; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrTOTPReplay):
			replayed++
		default:
			t.Fatalf("unexpected login error: %v", err)
		}
	}
	if succeeded != 1 || replayed != 1 {
		t.Fatalf("succeeded/replayed = %d/%d", succeeded, replayed)
	}
}

func TestRecoveryCodeIsAtomicallySingleUse(t *testing.T) {
	h := newIdentityHarness(t)
	code := h.owner.RecoveryCodes[0]
	challenges := []LoginChallenge{
		h.beginLogin(t, testPassword),
		h.beginLogin(t, testPassword),
	}

	start := make(chan struct{})
	type result struct {
		session Session
		err     error
	}
	results := make(chan result, len(challenges))
	var ready sync.WaitGroup
	ready.Add(len(challenges))
	for _, challenge := range challenges {
		go func() {
			ready.Done()
			<-start
			session, err := h.service.CompleteLogin(h.ctx, challenge.ID, code)
			results <- result{session: session, err: err}
		}()
	}
	ready.Wait()
	close(start)

	var succeeded, rejected int
	var recoverySession Session
	for range challenges {
		result := <-results
		switch {
		case result.err == nil:
			succeeded++
			recoverySession = result.session
		case errors.Is(result.err, ErrInvalidRecoveryCode):
			rejected++
		default:
			t.Fatalf("unexpected recovery login error: %v", result.err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("succeeded/rejected = %d/%d", succeeded, rejected)
	}
	principal, err := h.service.ResolveSession(h.ctx, recoverySession.RawToken)
	if err != nil {
		t.Fatal(err)
	}
	if principal.HasRecentTOTP(h.clock.Now()) {
		t.Fatal("recovery-code login incorrectly granted recent-TOTP status")
	}
}

func TestChallengeExpiresAfterFiveMinutes(t *testing.T) {
	h := newIdentityHarness(t)
	challenge := h.beginLogin(t, testPassword)
	h.clock.Advance(LoginChallengeLifetime)

	if _, err := h.service.CompleteLogin(
		h.ctx, challenge.ID, h.totpAt(h.clock.Now()),
	); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("expired challenge error = %v", err)
	}
}

func TestSessionIdleAbsoluteRecentTOTPAndRevocation(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		h := newIdentityHarness(t)
		session := h.login(t)
		h.clock.Advance(SessionIdleLifetime + time.Nanosecond)
		if _, err := h.service.ResolveSession(h.ctx, session.RawToken); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("idle expiry error = %v", err)
		}
	})

	t.Run("absolute despite activity", func(t *testing.T) {
		h := newIdentityHarness(t)
		session := h.login(t)
		for range 3 {
			h.clock.Advance(7 * time.Hour)
			if _, err := h.service.ResolveSession(h.ctx, session.RawToken); err != nil {
				t.Fatal(err)
			}
		}
		h.clock.Advance(3*time.Hour + time.Nanosecond)
		if _, err := h.service.ResolveSession(h.ctx, session.RawToken); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("absolute expiry error = %v", err)
		}
	})

	t.Run("recent TOTP and explicit revocation", func(t *testing.T) {
		h := newIdentityHarness(t)
		session := h.login(t)
		h.clock.Advance(RecentTOTPLifetime + time.Nanosecond)
		principal, err := h.service.ResolveSession(h.ctx, session.RawToken)
		if err != nil {
			t.Fatal(err)
		}
		if principal.HasRecentTOTP(h.clock.Now()) {
			t.Fatal("login TOTP remained recent beyond five minutes")
		}
		if _, err := h.service.VerifyRecentTOTP(
			h.ctx, session.RawToken, h.totpAt(h.clock.Now()),
		); err != nil {
			t.Fatal(err)
		}
		principal, err = h.service.ResolveSession(h.ctx, session.RawToken)
		if err != nil {
			t.Fatal(err)
		}
		if !principal.HasRecentTOTP(h.clock.Now()) {
			t.Fatal("recent TOTP timestamp was not persisted")
		}
		if err := h.service.RevokeUserSessions(h.ctx, h.owner.UserID); err != nil {
			t.Fatal(err)
		}
		if _, err := h.service.ResolveSession(h.ctx, session.RawToken); !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("revoked session error = %v", err)
		}
	})

	t.Run("recent TOTP expires at exact boundary", func(t *testing.T) {
		h := newIdentityHarness(t)
		session := h.login(t)
		h.clock.Advance(RecentTOTPLifetime)
		principal, err := h.service.ResolveSession(h.ctx, session.RawToken)
		if err != nil {
			t.Fatal(err)
		}
		if principal.HasRecentTOTP(h.clock.Now()) {
			t.Fatal("login TOTP remained recent at the exact five-minute boundary")
		}
	})

	t.Run("logout", func(t *testing.T) {
		h := newIdentityHarness(t)
		session := h.login(t)
		if err := h.service.Logout(h.ctx, session.RawToken); err != nil {
			t.Fatal(err)
		}
		if _, err := h.service.ResolveSession(h.ctx, session.RawToken); !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("logout error = %v", err)
		}
	})
}

func TestResetPasswordRevokesSessionsAndChangesCredential(t *testing.T) {
	h := newIdentityHarness(t)
	session := h.login(t)
	newPassword := "new correct horse battery staple"

	if err := h.service.ResetPassword(h.ctx, h.owner.UserID, newPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.ResolveSession(h.ctx, session.RawToken); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("old session error = %v", err)
	}
	if _, err := h.service.BeginLogin(h.ctx, testEmail, testPassword); err != ErrInvalidCredentials {
		t.Fatalf("old password error = %v", err)
	}
	if _, err := h.service.BeginLogin(h.ctx, testEmail, newPassword); err != nil {
		t.Fatalf("new password error = %v", err)
	}
}

func TestResetPasswordInvalidatesOutstandingLoginChallenge(t *testing.T) {
	h := newIdentityHarness(t)
	challenge := h.beginLogin(t, testPassword)

	if err := h.service.ResetPassword(
		h.ctx, h.owner.UserID, "replacement password fixture",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.CompleteLogin(
		h.ctx, challenge.ID, h.totpAt(h.clock.Now()),
	); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("pre-reset challenge error = %v", err)
	}
}

func TestChangeSystemRoleRequiresRecentTOTPFromActorSession(t *testing.T) {
	h := newIdentityHarness(t)
	session, err := h.service.CompleteLogin(
		h.ctx, h.beginLogin(t, testPassword).ID, h.owner.RecoveryCodes[0],
	)
	if err != nil {
		t.Fatal(err)
	}

	err = h.service.ChangeSystemRole(
		h.ctx, session.RawToken, h.owner.UserID, SystemRoleMember,
	)
	if !errors.Is(err, ErrRecentTOTPRequired) {
		t.Fatalf("role change error = %v", err)
	}
	if role := h.systemRole(t, h.owner.UserID); role != SystemRoleOwner {
		t.Fatalf("system role changed to %q", role)
	}
	if _, err := h.service.ResolveSession(h.ctx, session.RawToken); err != nil {
		t.Fatalf("actor session changed after rejected role change: %v", err)
	}
}

func TestChangeSystemRolePreservesOnlyActiveOwnerAndSessionOnRollback(t *testing.T) {
	h := newIdentityHarness(t)
	session := h.login(t)

	err := h.service.ChangeSystemRole(
		h.ctx, session.RawToken, h.owner.UserID, SystemRoleMember,
	)
	if !errors.Is(err, ErrLastSystemOwner) {
		t.Fatalf("unique-owner downgrade error = %v", err)
	}
	if role := h.systemRole(t, h.owner.UserID); role != SystemRoleOwner {
		t.Fatalf("system role changed to %q", role)
	}
	if _, err := h.service.ResolveSession(h.ctx, session.RawToken); err != nil {
		t.Fatalf("owner session was not rolled back: %v", err)
	}
}

func TestChangeSystemRoleCanPromoteSecondOwnerThenSafelyDemoteFirst(t *testing.T) {
	h := newIdentityHarness(t)
	firstOwnerSession := h.login(t)
	secondOwnerID := "second-owner"
	h.insertUser(t, secondOwnerID, SystemRoleMember)
	prePromotionToken := "second-owner-pre-promotion-session-fixture"
	h.insertSession(t, secondOwnerID, prePromotionToken, true)

	if err := h.service.ChangeSystemRole(
		h.ctx, firstOwnerSession.RawToken, secondOwnerID, SystemRoleOwner,
	); err != nil {
		t.Fatal(err)
	}
	if role := h.systemRole(t, secondOwnerID); role != SystemRoleOwner {
		t.Fatalf("second owner role = %q", role)
	}
	if _, err := h.service.ResolveSession(h.ctx, prePromotionToken); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("promoted target session error = %v", err)
	}

	secondOwnerSession := "second-owner-post-promotion-session-fixture"
	h.insertSession(t, secondOwnerID, secondOwnerSession, true)
	if err := h.service.ChangeSystemRole(
		h.ctx, secondOwnerSession, h.owner.UserID, SystemRoleMember,
	); err != nil {
		t.Fatal(err)
	}
	if role := h.systemRole(t, h.owner.UserID); role != SystemRoleMember {
		t.Fatalf("first owner role = %q", role)
	}
	if _, err := h.service.ResolveSession(
		h.ctx, firstOwnerSession.RawToken,
	); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("demoted target session error = %v", err)
	}
}

func TestChangeSystemRoleRejectsExpiredOrRevokedActorSessionWithoutTokenLeak(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		h := newIdentityHarness(t)
		session := h.login(t)
		h.clock.Advance(SessionIdleLifetime + time.Nanosecond)

		err := h.service.ChangeSystemRole(
			h.ctx, session.RawToken, h.owner.UserID, SystemRoleMember,
		)
		if !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("expired actor error = %v", err)
		}
		if strings.Contains(err.Error(), session.RawToken) {
			t.Fatal("expired-session error exposed raw token")
		}
	})

	t.Run("revoked", func(t *testing.T) {
		h := newIdentityHarness(t)
		session := h.login(t)
		if err := h.service.Logout(h.ctx, session.RawToken); err != nil {
			t.Fatal(err)
		}

		err := h.service.ChangeSystemRole(
			h.ctx, session.RawToken, h.owner.UserID, SystemRoleMember,
		)
		if !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("revoked actor error = %v", err)
		}
		if strings.Contains(err.Error(), session.RawToken) {
			t.Fatal("revoked-session error exposed raw token")
		}
	})
}

func TestSensitiveFixturesAreAbsentFromRawDatabase(t *testing.T) {
	h := newIdentityHarness(t)
	recoveryCode := h.owner.RecoveryCodes[0]
	session, err := h.service.CompleteLogin(
		h.ctx, h.beginLogin(t, testPassword).ID, recoveryCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Writer.ExecContext(h.ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for name, fixture := range map[string]string{
		"password":      testPassword,
		"TOTP seed":     testTOTPSeed,
		"recovery code": recoveryCode,
		"session token": session.RawToken,
	} {
		if bytes.Contains(raw, []byte(fixture)) {
			t.Fatalf("%s fixture found in database", name)
		}
	}
}

type identityHarness struct {
	ctx          context.Context
	databasePath string
	db           *storage.DB
	clock        *fakeClock
	service      *Service
	owner        CreateOwnerResult
}

func newIdentityHarness(t *testing.T) *identityHarness {
	t.Helper()
	h := newIdentityHarnessWithoutOwner(t)
	owner, err := h.service.CreateInitialOwner(h.ctx, CreateOwnerInput{
		Email: testEmail, Password: testPassword, TOTPSeed: testTOTPSeed,
		SourceIP: netip.MustParseAddr("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.owner = owner
	return h
}

func newIdentityHarnessWithKDF(t *testing.T, kdf passwordKDF) *identityHarness {
	t.Helper()
	h := newIdentityHarnessWithoutOwnerWithKDF(t, kdf)
	owner, err := h.service.CreateInitialOwner(h.ctx, CreateOwnerInput{
		Email: testEmail, Password: testPassword, TOTPSeed: testTOTPSeed,
		SourceIP: netip.MustParseAddr("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.owner = owner
	return h
}

func newIdentityHarnessWithoutOwner(t *testing.T) *identityHarness {
	return newIdentityHarnessWithoutOwnerWithKDF(t, nil)
}

func newIdentityHarnessWithoutOwnerWithKDF(
	t *testing.T,
	kdf passwordKDF,
) *identityHarness {
	t.Helper()
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "opswarden.db")
	db, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	clock := &fakeClock{now: time.Date(2026, 7, 28, 9, 30, 0, 0, time.UTC)}
	box := cryptobox.New([32]byte{1, 2, 3, 4})
	config := Config{InternalCIDRs: []netip.Prefix{netip.MustParsePrefix("10.23.0.0/16")}}
	var service *Service
	if kdf == nil {
		service, err = NewService(db, box, clock, config)
	} else {
		service, err = newServiceWithKDF(db, box, clock, config, kdf)
	}
	if err != nil {
		t.Fatal(err)
	}
	return &identityHarness{
		ctx: ctx, databasePath: databasePath, db: db, clock: clock, service: service,
	}
}

type passwordKDFCall struct {
	passwordParameters
	saltLength int
}

type recordingPasswordKDF struct {
	calls []passwordKDFCall
}

func (k *recordingPasswordKDF) derive(
	password, salt []byte,
	params passwordParameters,
) []byte {
	k.calls = append(k.calls, passwordKDFCall{
		passwordParameters: params,
		saltLength:         len(salt),
	})
	input := make([]byte, 0, len(password)+len(salt))
	input = append(input, password...)
	input = append(input, salt...)
	sum := sha256.Sum256(input)
	output := make([]byte, params.outputLength)
	for index := range output {
		output[index] = sum[index%len(sum)]
	}
	return output
}

func (k *recordingPasswordKDF) reset() {
	k.calls = nil
}

func testPasswordHash(
	t *testing.T,
	kdf passwordKDF,
	password string,
	params passwordParameters,
) []byte {
	t.Helper()
	salt := []byte("0123456789abcdef")
	sum := kdf([]byte(password), salt, params)
	return []byte(fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		params.memory, params.iterations, params.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	))
}

func (h *identityHarness) beginLogin(t *testing.T, password string) LoginChallenge {
	t.Helper()
	challenge, err := h.service.BeginLogin(h.ctx, testEmail, password)
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}

func (h *identityHarness) login(t *testing.T) Session {
	t.Helper()
	session, err := h.service.CompleteLogin(
		h.ctx, h.beginLogin(t, testPassword).ID, h.totpAt(h.clock.Now()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func (h *identityHarness) systemRole(t *testing.T, userID string) string {
	t.Helper()
	var role string
	if err := h.db.Reader.QueryRowContext(h.ctx,
		`SELECT system_role FROM users WHERE id = ?`, userID,
	).Scan(&role); err != nil {
		t.Fatal(err)
	}
	return role
}

func (h *identityHarness) insertUser(t *testing.T, userID, role string) {
	t.Helper()
	if _, err := h.db.Writer.ExecContext(h.ctx, `
		INSERT INTO users
			(id, email, normalized_email, password_hash, system_role, created_at, updated_at)
		VALUES (?, ?, ?, X'01', ?, ?, ?)
	`, userID, userID+"@example.com", userID+"@example.com", role,
		formatTime(h.clock.Now()), formatTime(h.clock.Now())); err != nil {
		t.Fatal(err)
	}
}

func (h *identityHarness) insertSession(
	t *testing.T,
	userID, rawToken string,
	recentTOTP bool,
) {
	t.Helper()
	tokenHash := sha256.Sum256([]byte(rawToken))
	now := h.clock.Now()
	var recentTOTPAt any
	if recentTOTP {
		recentTOTPAt = formatTime(now)
	}
	if _, err := h.db.Writer.ExecContext(h.ctx, `
		INSERT INTO sessions
			(id, user_id, token_hash, created_at, expires_at, idle_expires_at, recent_totp_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, "session-"+userID+"-"+rawToken, userID, tokenHash[:], formatTime(now),
		formatTime(now.Add(SessionAbsoluteLifetime)),
		formatTime(now.Add(SessionIdleLifetime)), recentTOTPAt); err != nil {
		t.Fatal(err)
	}
}

func (h *identityHarness) totpAt(at time.Time) string {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(testTOTPSeed)
	if err != nil {
		panic(err)
	}
	counter := uint64(at.Unix() / int64(TOTPPeriod/time.Second))
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", value)
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}
