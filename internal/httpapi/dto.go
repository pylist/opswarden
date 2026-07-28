package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBodyLimit    = int64(64 << 10)
	credentialBodyLimit = int64(1 << 20)
)

type requestMetadata struct {
	requestID string
	sourceIP  string
	userAgent string
}

type metadataContextKey struct{}

func requestMetadataFromContext(ctx context.Context) requestMetadata {
	metadata, _ := ctx.Value(metadataContextKey{}).(requestMetadata)
	return metadata
}

func decodeJSONBody(
	writer http.ResponseWriter,
	request *http.Request,
	limit int64,
	destination any,
) error {
	if request.Header.Get("Content-Encoding") != "" {
		return errors.New("encoded request bodies are not supported")
	}
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	if request.Body == nil {
		return errors.New("request body is required")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, limit)
	encoded, err := io.ReadAll(request.Body)
	if err != nil || len(bytes.TrimSpace(encoded)) == 0 {
		return errors.New("invalid JSON body")
	}
	if err := rejectDuplicateJSONKeys(encoded); err != nil {
		return err
	}
	if err := validateCanonicalTopLevelFields(encoded, destination); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid JSON body")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON document")
	}
	return nil
}

func validateCanonicalTopLevelFields(encoded []byte, destination any) error {
	value := reflect.ValueOf(destination)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return errors.New("JSON destination must be a pointer")
	}
	typ := value.Elem().Type()
	if typ.Kind() != reflect.Struct {
		return errors.New("JSON destination must point to a struct")
	}
	allowed := make(map[string]struct{}, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == "" {
			tag = field.Name
		}
		if tag != "-" {
			allowed[tag] = struct{}{}
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || fields == nil {
		return errors.New("JSON body must be an object")
	}
	for key := range fields {
		if _, ok := allowed[key]; !ok {
			return errors.New("unknown or non-canonical JSON field")
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return errors.New("invalid JSON body")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON document")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return errors.New("duplicate JSON key")
			}
			keys[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func parseQuery(
	request *http.Request,
	allowed ...string,
) (map[string]string, error) {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return nil, errors.New("invalid query")
	}
	result := make(map[string]string, len(query))
	for key, values := range query {
		if _, ok := allowedSet[key]; !ok || len(values) != 1 ||
			values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
			return nil, errors.New("invalid query")
		}
		result[key] = values[0]
	}
	return result, nil
}

func queryInt(values map[string]string, key string) (int, error) {
	if values[key] == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(values[key])
	if err != nil || strconv.Itoa(parsed) != values[key] {
		return 0, errors.New("invalid integer query")
	}
	return parsed, nil
}

func queryBool(values map[string]string, key string) (bool, error) {
	if values[key] == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(values[key])
	if err != nil || (values[key] != "true" && values[key] != "false") {
		return false, errors.New("invalid boolean query")
	}
	return parsed, nil
}

func parseRFC3339(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return parsed, nil
}
