package credentials

import (
	"errors"
	"testing"
)

func TestValidatePayloadRejectsUnknownFields(t *testing.T) {
	tests := map[Type]string{
		TypeLogin:    `{"url":"https://example.test","username":"alice","password":"password","unknown":"value"}`,
		TypeAPIToken: `{"service":"example","token":"token","unknown":"value"}`,
		TypeSSHKey:   `{"username":"root","private_key":"private","unknown":"value"}`,
		TypeDatabase: `{"engine":"postgres","host":"db.test","unknown":"value"}`,
		TypeTOTP:     `{"issuer":"Example","account":"alice","seed":"seed","algorithm":"SHA1","digits":6,"period":30,"unknown":"value"}`,
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

func TestValidatePayloadRejectsCaseVariantFieldCollisions(t *testing.T) {
	tests := map[Type]string{
		TypeLogin:    `{"url":"https://example.test","username":"alice","password":"one","Password":"two"}`,
		TypeAPIToken: `{"service":"example","token":"one","Token":"two"}`,
		TypeSSHKey:   `{"username":"root","private_key":"one","Private_Key":"two"}`,
		TypeDatabase: `{"engine":"postgres","Engine":"mysql","host":"db.test"}`,
		TypeTOTP:     `{"issuer":"Example","account":"alice","seed":"one","Seed":"two","algorithm":"SHA1","digits":6,"period":30}`,
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

func TestDatabaseParameterKeysAreCaseSensitiveBusinessKeys(t *testing.T) {
	got, err := ValidatePayload(TypeDatabase, []byte(
		`{"engine":"postgres","host":"db.test","parameters":{"Mode":"one","mode":"two"}}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("validated payload is empty")
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
