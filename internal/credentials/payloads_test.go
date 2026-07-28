package credentials

import (
	"errors"
	"testing"
)

func TestValidatePayloadRejectsUnknownFields(t *testing.T) {
	for _, credentialType := range []Type{
		TypeLogin, TypeAPIToken, TypeSSHKey, TypeDatabase, TypeTOTP,
	} {
		t.Run(string(credentialType), func(t *testing.T) {
			_, err := ValidatePayload(credentialType, []byte(`{"unknown":"fixture-password"}`))
			if !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestValidatePayloadRejectsDuplicateTopLevelFields(t *testing.T) {
	tests := map[Type]string{
		TypeLogin:    `{"url":"https://one.test","url":"https://two.test","username":"alice","password":"password"}`,
		TypeAPIToken: `{"service":"one","service":"two","token":"token"}`,
		TypeSSHKey:   `{"username":"root","username":"admin","private_key":"private"}`,
		TypeDatabase: `{"engine":"postgres","engine":"mysql","host":"db.test"}`,
		TypeTOTP:     `{"issuer":"one","issuer":"two","account":"alice","seed":"seed","algorithm":"SHA1","digits":6,"period":30}`,
	}
	for credentialType, raw := range tests {
		t.Run(string(credentialType), func(t *testing.T) {
			_, err := ValidatePayload(credentialType, []byte(raw))
			if !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestValidatePayloadRejectsNestedDuplicateFields(t *testing.T) {
	_, err := ValidatePayload(TypeDatabase, []byte(
		`{"engine":"postgres","host":"db.test","parameters":{"sslmode":"require","sslmode":"disable"}}`,
	))
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("got %v", err)
	}
}

func TestValidatePayloadAcceptsTypedPayloads(t *testing.T) {
	tests := map[Type]string{
		TypeLogin:    `{"url":"https://example.test","username":"alice","password":"fixture-password"}`,
		TypeAPIToken: `{"service":"example","token":"fixture-token","header_name":"Authorization"}`,
		TypeSSHKey:   `{"username":"root","private_key":"fixture-private-key","public_key":"ssh-ed25519 AAAA","fingerprint":"SHA256:abc"}`,
		TypeDatabase: `{"engine":"postgres","host":"db.example.test","port":5432,"database":"app","username":"app","password":"fixture-db-password","parameters":{"sslmode":"require"},"connection_string":"fixture-connection-string"}`,
		TypeTOTP:     `{"issuer":"Example","account":"alice@example.test","seed":"fixture-totp-seed","algorithm":"SHA1","digits":6,"period":30}`,
	}
	for credentialType, raw := range tests {
		t.Run(string(credentialType), func(t *testing.T) {
			got, err := ValidatePayload(credentialType, []byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) == 0 {
				t.Fatal("validated payload is empty")
			}
		})
	}
}

func TestValidatePayloadRejectsTrailingJSON(t *testing.T) {
	_, err := ValidatePayload(
		TypeLogin,
		[]byte(`{"url":"https://example.test","username":"alice","password":"p"} {}`),
	)
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("got %v", err)
	}
}
