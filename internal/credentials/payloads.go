package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

type LoginPayload struct {
	URL              string `json:"url"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	TOTPCredentialID string `json:"totp_credential_id,omitempty"`
}

type APITokenPayload struct {
	Service    string `json:"service"`
	Token      string `json:"token"`
	HeaderName string `json:"header_name,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type SSHKeyPayload struct {
	Username    string `json:"username"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Passphrase  string `json:"passphrase,omitempty"`
}

type DatabasePayload struct {
	Engine           string            `json:"engine"`
	Host             string            `json:"host,omitempty"`
	Port             uint16            `json:"port,omitempty"`
	Database         string            `json:"database,omitempty"`
	Username         string            `json:"username,omitempty"`
	Password         string            `json:"password,omitempty"`
	Parameters       map[string]string `json:"parameters,omitempty"`
	ConnectionString string            `json:"connection_string,omitempty"`
}

type TOTPPayload struct {
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Seed      string `json:"seed"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
}

func ValidatePayload(credentialType Type, raw json.RawMessage) (json.RawMessage, error) {
	if !credentialType.Valid() || len(raw) == 0 || len(raw) > 1024*1024 {
		return nil, ErrInvalidPayload
	}
	switch credentialType {
	case TypeLogin:
		var payload LoginPayload
		if strictDecode(raw, &payload) != nil ||
			blank(payload.URL) || blank(payload.Username) || payload.Password == "" {
			return nil, ErrInvalidPayload
		}
		return canonicalPayload(payload)
	case TypeAPIToken:
		var payload APITokenPayload
		if strictDecode(raw, &payload) != nil ||
			blank(payload.Service) || payload.Token == "" {
			return nil, ErrInvalidPayload
		}
		if payload.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, payload.ExpiresAt); err != nil {
				return nil, ErrInvalidPayload
			}
		}
		return canonicalPayload(payload)
	case TypeSSHKey:
		var payload SSHKeyPayload
		if strictDecode(raw, &payload) != nil ||
			blank(payload.Username) || payload.PrivateKey == "" {
			return nil, ErrInvalidPayload
		}
		return canonicalPayload(payload)
	case TypeDatabase:
		var payload DatabasePayload
		if strictDecode(raw, &payload) != nil || blank(payload.Engine) ||
			(blank(payload.Host) && payload.ConnectionString == "") {
			return nil, ErrInvalidPayload
		}
		for key := range payload.Parameters {
			if blank(key) {
				return nil, ErrInvalidPayload
			}
		}
		return canonicalPayload(payload)
	case TypeTOTP:
		var payload TOTPPayload
		if strictDecode(raw, &payload) != nil ||
			blank(payload.Issuer) || blank(payload.Account) || payload.Seed == "" ||
			!validTOTPAlgorithm(payload.Algorithm) ||
			(payload.Digits != 6 && payload.Digits != 8) ||
			payload.Period < 1 || payload.Period > 300 {
			return nil, ErrInvalidPayload
		}
		return canonicalPayload(payload)
	default:
		return nil, ErrInvalidPayload
	}
}

func strictDecode(raw []byte, destination any) error {
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidPayload
	}
	return nil
}

func rejectDuplicateJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return ErrInvalidPayload
	}
	if err := consumeJSONValue(decoder, first); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidPayload
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrInvalidPayload
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidPayload
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidPayload
			}
			seen[key] = struct{}{}
			valueToken, err := decoder.Token()
			if err != nil {
				return ErrInvalidPayload
			}
			if err := consumeJSONValue(decoder, valueToken); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidPayload
		}
	case '[':
		for decoder.More() {
			valueToken, err := decoder.Token()
			if err != nil {
				return ErrInvalidPayload
			}
			if err := consumeJSONValue(decoder, valueToken); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidPayload
		}
	default:
		return ErrInvalidPayload
	}
	return nil
}

func canonicalPayload(payload any) (json.RawMessage, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalidPayload
	}
	return json.RawMessage(encoded), nil
}

func blank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func validTOTPAlgorithm(algorithm string) bool {
	switch algorithm {
	case "SHA1", "SHA256", "SHA512":
		return true
	default:
		return false
	}
}
