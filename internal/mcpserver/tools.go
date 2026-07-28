package mcpserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"opswarden/internal/apierrors"
	"opswarden/internal/assets"
	"opswarden/internal/audit"
	"opswarden/internal/credentials"
)

const maxToolArgumentDepth = 16

var ErrInvalidToolInput = errors.New("invalid MCP tool input")
var ErrInvalidToolOutput = errors.New("invalid MCP tool output")

var approvedToolNames = []string{
	"asset_get",
	"asset_list",
	"credential_create",
	"credential_delete",
	"credential_get",
	"credential_list",
	"credential_update",
	"totp_generate",
}

// ToolNames returns the fixed, approved MCP tool surface in lexical order.
func ToolNames() []string {
	return slices.Clone(approvedToolNames)
}

type credentialListInput struct {
	SpaceID        string            `json:"space_id"`
	Type           credentials.Type  `json:"type,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
	IncludeDeleted bool              `json:"include_deleted,omitempty"`
	DeletedOnly    bool              `json:"deleted_only,omitempty"`
	After          string            `json:"after,omitempty"`
	Limit          int               `json:"limit,omitempty"`
}

type credentialGetInput struct {
	SpaceID      string `json:"space_id"`
	CredentialID string `json:"credential_id"`
}

type credentialCreateInput struct {
	SpaceID        string            `json:"space_id"`
	DisplayName    string            `json:"display_name"`
	Type           credentials.Type  `json:"type"`
	Tags           map[string]string `json:"tags,omitempty"`
	AssetIDs       []string          `json:"asset_ids,omitempty"`
	Payload        json.RawMessage   `json:"payload"`
	Reason         string            `json:"reason"`
	IdempotencyKey string            `json:"idempotency_key"`
}

type credentialUpdateInput struct {
	SpaceID        string            `json:"space_id"`
	CredentialID   string            `json:"credential_id"`
	Expected       uint64            `json:"expected_version"`
	DisplayName    *string           `json:"display_name,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
	AssetIDs       []string          `json:"asset_ids,omitempty"`
	Payload        json.RawMessage   `json:"payload,omitempty"`
	Reason         string            `json:"reason"`
	IdempotencyKey string            `json:"idempotency_key"`
}

type credentialDeleteInput struct {
	SpaceID        string `json:"space_id"`
	CredentialID   string `json:"credential_id"`
	Expected       uint64 `json:"expected_version"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotency_key"`
}

type assetListInput struct {
	SpaceID     string            `json:"space_id"`
	Type        string            `json:"type,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Status      string            `json:"status,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	After       string            `json:"after,omitempty"`
	Limit       int               `json:"limit,omitempty"`
}

type assetGetInput struct {
	SpaceID string `json:"space_id"`
	AssetID string `json:"asset_id"`
}

type totpGenerateInput struct {
	SpaceID      string `json:"space_id"`
	CredentialID string `json:"credential_id"`
}

type credentialMetadataOutput struct {
	ID          string            `json:"id"`
	SpaceID     string            `json:"space_id"`
	DisplayName string            `json:"display_name"`
	Type        credentials.Type  `json:"type"`
	Version     uint64            `json:"version"`
	Tags        map[string]string `json:"tags"`
	AssetIDs    []string          `json:"asset_ids"`
	DeletedAt   *time.Time        `json:"deleted_at,omitempty"`
}

type assetOutput struct {
	ID          string            `json:"id"`
	SpaceID     string            `json:"space_id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Hostname    string            `json:"hostname"`
	OS          string            `json:"os"`
	Environment string            `json:"environment"`
	Status      string            `json:"status"`
	IPs         []netip.Addr      `json:"ips"`
	Ports       []uint16          `json:"ports"`
	Tags        map[string]string `json:"tags"`
	Notes       string            `json:"notes"`
	Version     uint64            `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	DeletedAt   *time.Time        `json:"deleted_at,omitempty"`
}

func registerTools(server *mcp.Server, dependencies Dependencies) error {
	readOnly := true
	closedWorld := false
	var registrationError error
	add := func(tool *mcp.Tool, handler toolHandler) {
		if registrationError != nil {
			return
		}
		registrationError = addRawTool(server, tool, dependencies, handler)
	}
	add(&mcp.Tool{
		Name:         "credential_list",
		Description:  "列出凭据元数据；绝不返回凭据明文。",
		InputSchema:  schemaCredentialList,
		OutputSchema: schemaCredentialListOutput,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: readOnly, OpenWorldHint: &closedWorld,
		},
	}, handleCredentialList)
	add(&mcp.Tool{
		Name: "credential_get",
		Description: "读取一个凭据及其敏感明文。结果必须作为敏感数据处理，" +
			"不得记录、缓存或转发。",
		InputSchema:  schemaCredentialGet,
		OutputSchema: schemaCredentialGetOutput,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: readOnly, OpenWorldHint: &closedWorld,
		},
	}, handleCredentialGet)
	add(&mcp.Tool{
		Name: "credential_create", Description: "创建凭据；payload 是敏感数据。",
		InputSchema:  schemaCredentialCreate,
		OutputSchema: schemaMutationOutput,
		Annotations: &mcp.ToolAnnotations{
			IdempotentHint: true, OpenWorldHint: &closedWorld,
		},
	}, handleCredentialCreate)
	add(&mcp.Tool{
		Name: "credential_update", Description: "按版本更新凭据；payload 是敏感数据。",
		InputSchema:  schemaCredentialUpdate,
		OutputSchema: schemaMutationOutput,
		Annotations: &mcp.ToolAnnotations{
			IdempotentHint: true, OpenWorldHint: &closedWorld,
		},
	}, handleCredentialUpdate)
	add(&mcp.Tool{
		Name: "credential_delete", Description: "按版本将凭据移入回收站。",
		InputSchema:  schemaCredentialDelete,
		OutputSchema: schemaDeleteOutput,
		Annotations: &mcp.ToolAnnotations{
			IdempotentHint: true, OpenWorldHint: &closedWorld,
		},
	}, handleCredentialDelete)
	add(&mcp.Tool{
		Name: "totp_generate",
		Description: "从 TOTP 凭据生成当前一次性验证码。结果是敏感数据；" +
			"只返回当前 code 和 expiry，不返回 seed。",
		InputSchema:  schemaTOTPGenerate,
		OutputSchema: schemaTOTPOutput,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: readOnly, OpenWorldHint: &closedWorld,
		},
	}, handleTOTPGenerate)
	add(&mcp.Tool{
		Name: "asset_list", Description: "列出资产。",
		InputSchema:  schemaAssetList,
		OutputSchema: schemaAssetListOutput,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: readOnly, OpenWorldHint: &closedWorld,
		},
	}, handleAssetList)
	add(&mcp.Tool{
		Name: "asset_get", Description: "读取一个资产。",
		InputSchema:  schemaAssetGet,
		OutputSchema: schemaAssetOutput,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: readOnly, OpenWorldHint: &closedWorld,
		},
	}, handleAssetGet)
	return registrationError
}

type toolHandler func(
	context.Context,
	Dependencies,
	requestContext,
	json.RawMessage,
) (any, error)

func addRawTool(
	server *mcp.Server,
	tool *mcp.Tool,
	dependencies Dependencies,
	call toolHandler,
) error {
	rawOutputSchema, ok := tool.OutputSchema.(json.RawMessage)
	if !ok {
		return errors.New("MCP tool output schema must be raw JSON")
	}
	outputValidator, err := compileOutputSchema(rawOutputSchema)
	if err != nil {
		return errors.New("compile MCP tool output schema")
	}
	server.AddTool(tool, func(
		ctx context.Context,
		request *mcp.CallToolRequest,
	) (*mcp.CallToolResult, error) {
		authenticated, ok := ctx.Value(requestContextKey{}).(requestContext)
		if !ok || authenticated.principal.AgentID == "" ||
			authenticated.principal.TokenID == "" {
			return toolError("UNAUTHENTICATED"), nil
		}
		result, err := call(
			ctx, dependencies, authenticated, request.Params.Arguments,
		)
		if err != nil {
			return toolError(toolErrorCode(err)), nil
		}
		success, err := toolSuccess(result, outputValidator)
		if err != nil {
			return toolError("INTERNAL_ERROR"), nil
		}
		return success, nil
	})
	return nil
}

func handleCredentialList(
	ctx context.Context,
	dependencies Dependencies,
	authenticated requestContext,
	raw json.RawMessage,
) (any, error) {
	if dependencies.Credentials == nil {
		return nil, audit.ErrAuditUnavailable
	}
	var input credentialListInput
	if err := decodeExact(raw, &input); err != nil || blank(input.SpaceID) {
		return nil, ErrInvalidToolInput
	}
	principal := credentialPrincipal(authenticated, input.SpaceID)
	items, next, err := dependencies.Credentials.List(
		ctx, principal, credentials.ListFilter{
			SpaceID: input.SpaceID, Type: input.Type, Tags: input.Tags,
			IncludeDeleted: input.IncludeDeleted, DeletedOnly: input.DeletedOnly,
			After: input.After, Limit: input.Limit,
		},
	)
	if err != nil {
		return nil, err
	}
	output := make([]credentialMetadataOutput, 0, len(items))
	for _, item := range items {
		if item.SpaceID != input.SpaceID {
			return nil, credentials.ErrNotFound
		}
		output = append(output, credentialMetadataDTO(item))
	}
	return struct {
		Items      []credentialMetadataOutput `json:"items"`
		NextCursor string                     `json:"next_cursor,omitempty"`
	}{Items: output, NextCursor: next}, nil
}

func handleCredentialGet(
	ctx context.Context,
	dependencies Dependencies,
	authenticated requestContext,
	raw json.RawMessage,
) (any, error) {
	if dependencies.Credentials == nil {
		return nil, audit.ErrAuditUnavailable
	}
	var input credentialGetInput
	if err := decodeExact(raw, &input); err != nil ||
		blank(input.SpaceID) || blank(input.CredentialID) {
		return nil, ErrInvalidToolInput
	}
	decrypted, err := dependencies.Credentials.Get(
		ctx, credentialPrincipal(authenticated, input.SpaceID), input.CredentialID,
	)
	if err != nil {
		clear(decrypted.Payload)
		return nil, err
	}
	defer clear(decrypted.Payload)
	if decrypted.Metadata.SpaceID != input.SpaceID {
		return nil, credentials.ErrNotFound
	}
	payload := append(json.RawMessage(nil), decrypted.Payload...)
	return struct {
		Metadata credentialMetadataOutput `json:"metadata"`
		Payload  json.RawMessage          `json:"payload"`
	}{Metadata: credentialMetadataDTO(decrypted.Metadata), Payload: payload}, nil
}

func handleCredentialCreate(
	ctx context.Context,
	dependencies Dependencies,
	authenticated requestContext,
	raw json.RawMessage,
) (any, error) {
	defer clear(raw)
	if dependencies.Credentials == nil {
		return nil, audit.ErrAuditUnavailable
	}
	var input credentialCreateInput
	if err := decodeExact(raw, &input); err != nil ||
		blank(input.SpaceID) || blank(input.DisplayName) ||
		blank(string(input.Type)) || len(input.Payload) == 0 ||
		blank(input.Reason) || blank(input.IdempotencyKey) {
		return nil, ErrInvalidToolInput
	}
	defer clear(input.Payload)
	principal := credentialPrincipal(authenticated, input.SpaceID)
	result, err := dependencies.Credentials.Create(
		ctx, principal, credentials.CreateInput{
			SpaceID: input.SpaceID, DisplayName: input.DisplayName,
			Type: input.Type, Tags: input.Tags, AssetIDs: input.AssetIDs,
			Payload: input.Payload,
		},
		credentials.WriteContext{
			Actor: authenticated.actor, Reason: input.Reason,
			IdempotencyKey: input.IdempotencyKey,
		},
	)
	if err != nil {
		return nil, err
	}
	return mutationDTO(result), nil
}

func handleCredentialUpdate(
	ctx context.Context,
	dependencies Dependencies,
	authenticated requestContext,
	raw json.RawMessage,
) (any, error) {
	defer clear(raw)
	if dependencies.Credentials == nil {
		return nil, audit.ErrAuditUnavailable
	}
	var input credentialUpdateInput
	if err := decodeExact(raw, &input); err != nil ||
		blank(input.SpaceID) || blank(input.CredentialID) || input.Expected == 0 ||
		blank(input.Reason) || blank(input.IdempotencyKey) {
		return nil, ErrInvalidToolInput
	}
	defer clear(input.Payload)
	result, err := dependencies.Credentials.Update(
		ctx, credentialPrincipal(authenticated, input.SpaceID),
		credentials.UpdateInput{
			CredentialID: input.CredentialID, ExpectedVersion: input.Expected,
			DisplayName: input.DisplayName, Tags: input.Tags,
			AssetIDs: input.AssetIDs, Payload: input.Payload,
		},
		credentials.WriteContext{
			Actor: authenticated.actor, Reason: input.Reason,
			IdempotencyKey: input.IdempotencyKey,
		},
	)
	if err != nil {
		return nil, err
	}
	return mutationDTO(result), nil
}

func handleCredentialDelete(
	ctx context.Context,
	dependencies Dependencies,
	authenticated requestContext,
	raw json.RawMessage,
) (any, error) {
	if dependencies.Credentials == nil {
		return nil, audit.ErrAuditUnavailable
	}
	var input credentialDeleteInput
	if err := decodeExact(raw, &input); err != nil ||
		blank(input.SpaceID) || blank(input.CredentialID) || input.Expected == 0 ||
		blank(input.Reason) || blank(input.IdempotencyKey) {
		return nil, ErrInvalidToolInput
	}
	err := dependencies.Credentials.Delete(
		ctx, credentialPrincipal(authenticated, input.SpaceID),
		input.CredentialID, input.Expected,
		credentials.WriteContext{
			Actor: authenticated.actor, Reason: input.Reason,
			IdempotencyKey: input.IdempotencyKey,
		},
	)
	if err != nil {
		return nil, err
	}
	return struct {
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
	}{ID: input.CredentialID, Deleted: true}, nil
}

func handleAssetList(
	ctx context.Context,
	dependencies Dependencies,
	authenticated requestContext,
	raw json.RawMessage,
) (any, error) {
	if dependencies.Assets == nil {
		return nil, assets.ErrUnavailable
	}
	var input assetListInput
	if err := decodeExact(raw, &input); err != nil || blank(input.SpaceID) {
		return nil, ErrInvalidToolInput
	}
	items, next, err := dependencies.Assets.List(
		ctx, credentialPrincipal(authenticated, input.SpaceID),
		assets.ListFilter{
			SpaceID: input.SpaceID, Type: input.Type,
			Environment: input.Environment, Status: input.Status,
			Tags: input.Tags, After: input.After, Limit: input.Limit,
		},
	)
	if err != nil {
		return nil, err
	}
	output := make([]assetOutput, 0, len(items))
	for _, item := range items {
		if item.SpaceID != input.SpaceID {
			return nil, assets.ErrNotFound
		}
		output = append(output, assetDTO(item))
	}
	return struct {
		Items      []assetOutput `json:"items"`
		NextCursor string        `json:"next_cursor,omitempty"`
	}{Items: output, NextCursor: next}, nil
}

func handleAssetGet(
	ctx context.Context,
	dependencies Dependencies,
	authenticated requestContext,
	raw json.RawMessage,
) (any, error) {
	if dependencies.Assets == nil {
		return nil, assets.ErrUnavailable
	}
	var input assetGetInput
	if err := decodeExact(raw, &input); err != nil ||
		blank(input.SpaceID) || blank(input.AssetID) {
		return nil, ErrInvalidToolInput
	}
	item, err := dependencies.Assets.Get(
		ctx, credentialPrincipal(authenticated, input.SpaceID), input.AssetID,
	)
	if err != nil {
		return nil, err
	}
	if item.SpaceID != input.SpaceID {
		return nil, assets.ErrNotFound
	}
	return assetDTO(item), nil
}

func handleTOTPGenerate(
	ctx context.Context,
	dependencies Dependencies,
	authenticated requestContext,
	raw json.RawMessage,
) (any, error) {
	if dependencies.Credentials == nil {
		return nil, audit.ErrAuditUnavailable
	}
	var input totpGenerateInput
	if err := decodeExact(raw, &input); err != nil ||
		blank(input.SpaceID) || blank(input.CredentialID) {
		return nil, ErrInvalidToolInput
	}
	decrypted, err := dependencies.Credentials.Get(
		ctx, credentialPrincipal(authenticated, input.SpaceID), input.CredentialID,
	)
	if err != nil {
		clear(decrypted.Payload)
		return nil, err
	}
	defer clear(decrypted.Payload)
	if decrypted.Metadata.SpaceID != input.SpaceID ||
		decrypted.Metadata.Type != credentials.TypeTOTP {
		return nil, credentials.ErrNotFound
	}
	canonical, err := credentials.ValidatePayload(
		credentials.TypeTOTP, decrypted.Payload,
	)
	if err != nil {
		return nil, credentials.ErrNotFound
	}
	defer clear(canonical)
	var payload credentials.TOTPPayload
	if err := json.Unmarshal(canonical, &payload); err != nil {
		payload.Seed = ""
		return nil, credentials.ErrNotFound
	}
	now := dependencies.Clock.Now().UTC()
	code, expiry, err := generateTOTP(payload, now)
	payload.Seed = ""
	if err != nil {
		return nil, credentials.ErrNotFound
	}
	defer clear(code)
	if err := dependencies.AuthAudit.RecordReadBeforeReturn(
		ctx, audit.Event{
			ID: newID("aud_"), RequestID: authenticated.requestID,
			CreatedAt: now,
			Actor:     authenticated.actor, Action: "credential.totp.generate",
			SpaceID: input.SpaceID, ResourceType: "credential",
			ResourceID: input.CredentialID, SourceIP: authenticated.sourceIP,
			UserAgent: authenticated.userAgent, Success: true,
		},
	); err != nil {
		return nil, audit.ErrAuditUnavailable
	}
	return struct {
		Code   string    `json:"code"`
		Expiry time.Time `json:"expiry"`
	}{Code: string(code), Expiry: expiry}, nil
}

func credentialPrincipal(
	authenticated requestContext,
	spaceID string,
) credentials.Principal {
	agent := authenticated.principal.AuthorizationPrincipal()
	return credentials.Principal{
		Agent: &agent, BoundSpaceID: spaceID, Actor: authenticated.actor,
		RequestID: authenticated.requestID, SourceIP: authenticated.sourceIP,
		UserAgent: authenticated.userAgent,
	}
}

func credentialMetadataDTO(
	metadata credentials.Metadata,
) credentialMetadataOutput {
	tags := maps.Clone(metadata.Tags)
	if tags == nil {
		tags = map[string]string{}
	}
	assetIDs := slices.Clone(metadata.AssetIDs)
	if assetIDs == nil {
		assetIDs = []string{}
	}
	return credentialMetadataOutput{
		ID: metadata.ID, SpaceID: metadata.SpaceID,
		DisplayName: metadata.DisplayName, Type: metadata.Type,
		Version: metadata.Version, Tags: tags, AssetIDs: assetIDs,
		DeletedAt: metadata.DeletedAt,
	}
}

func assetDTO(item assets.Asset) assetOutput {
	ips := slices.Clone(item.IPs)
	if ips == nil {
		ips = []netip.Addr{}
	}
	ports := slices.Clone(item.Ports)
	if ports == nil {
		ports = []uint16{}
	}
	tags := maps.Clone(item.Tags)
	if tags == nil {
		tags = map[string]string{}
	}
	return assetOutput{
		ID: item.ID, SpaceID: item.SpaceID, Name: item.Name, Type: item.Type,
		Hostname: item.Hostname, OS: item.OS, Environment: item.Environment,
		Status: item.Status, IPs: ips, Ports: ports, Tags: tags,
		Notes: item.Notes, Version: item.Version, CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt, DeletedAt: item.DeletedAt,
	}
}

func mutationDTO(result credentials.MutationResult) any {
	return struct {
		ID      string `json:"id"`
		Version uint64 `json:"version"`
		Status  int    `json:"status"`
	}{ID: result.ID, Version: result.Version, Status: result.Status}
}

func compileOutputSchema(raw json.RawMessage) (*jsonschema.Resolved, error) {
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, ErrInvalidToolOutput
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		return nil, ErrInvalidToolOutput
	}
	return resolved, nil
}

func toolSuccess(
	value any,
	validator *jsonschema.Resolved,
) (*mcp.CallToolResult, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidToolOutput
	}
	var instance any
	if json.Unmarshal(encoded, &instance) != nil ||
		validator == nil || validator.Validate(instance) != nil {
		clear(encoded)
		return nil, ErrInvalidToolOutput
	}
	text := string(encoded)
	clear(encoded)
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: text}},
		StructuredContent: value,
	}, nil
}

func toolError(code string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: code}},
		IsError: true,
	}
}

func toolErrorCode(err error) string {
	if errors.Is(err, ErrInvalidToolInput) {
		return "INVALID_INPUT"
	}
	classification := apierrors.Classify(err)
	if classification.Code == apierrors.CodeInvalidRequest {
		return "INVALID_INPUT"
	}
	return string(classification.Code)
}

func decodeExact(raw json.RawMessage, destination any) error {
	if len(raw) == 0 || len(raw) > int(maxRequestBytes) {
		return ErrInvalidToolInput
	}
	if err := validateJSONShape(raw); err != nil {
		return err
	}
	if err := validateCanonicalFields(raw, destination); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidToolInput
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidToolInput
	}
	return nil
}

func validateCanonicalFields(raw []byte, destination any) error {
	value := reflect.ValueOf(destination)
	if value.Kind() != reflect.Pointer || value.IsNil() ||
		value.Elem().Kind() != reflect.Struct {
		return ErrInvalidToolInput
	}
	typ := value.Elem().Type()
	allowed := make(map[string]struct{}, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		tag := strings.Split(typ.Field(index).Tag.Get("json"), ",")[0]
		if tag == "" {
			tag = typ.Field(index).Name
		}
		if tag != "-" {
			allowed[tag] = struct{}{}
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return ErrInvalidToolInput
	}
	for field := range fields {
		if _, ok := allowed[field]; !ok {
			return ErrInvalidToolInput
		}
	}
	return nil
}

func validateJSONShape(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSON(decoder, 0); err != nil {
		return ErrInvalidToolInput
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidToolInput
	}
	return nil
}

func consumeJSON(decoder *json.Decoder, depth int) error {
	if depth > maxToolArgumentDepth {
		return ErrInvalidToolInput
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidToolInput
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidToolInput
			}
			seen[key] = struct{}{}
			if err := consumeJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalidToolInput
		}
	case '[':
		for decoder.More() {
			if err := consumeJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalidToolInput
		}
	default:
		return ErrInvalidToolInput
	}
	return nil
}

func generateTOTP(
	payload credentials.TOTPPayload,
	now time.Time,
) ([]byte, time.Time, error) {
	if now.IsZero() || payload.Period < 1 || payload.Period > 300 ||
		now.Before(time.Unix(0, 0)) ||
		(payload.Digits != 6 && payload.Digits != 8) ||
		strings.TrimSpace(payload.Seed) != payload.Seed ||
		payload.Seed == "" {
		return nil, time.Time{}, ErrInvalidToolInput
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret, err := encoding.DecodeString(payload.Seed)
	if err != nil || encoding.EncodeToString(secret) != payload.Seed {
		clear(secret)
		return nil, time.Time{}, ErrInvalidToolInput
	}
	defer clear(secret)
	var newHash func() hash.Hash
	switch payload.Algorithm {
	case "SHA1":
		newHash = sha1.New
	case "SHA256":
		newHash = sha256.New
	case "SHA512":
		newHash = sha512.New
	default:
		return nil, time.Time{}, ErrInvalidToolInput
	}
	counter := uint64(now.Unix() / int64(payload.Period))
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac := hmac.New(newHash, secret)
	_, _ = mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	clear(sum)
	modulus := uint32(1_000_000)
	if payload.Digits == 8 {
		modulus = 100_000_000
	}
	digits := strconv.FormatUint(uint64(value%modulus), 10)
	code := make([]byte, payload.Digits)
	for index := range code {
		code[index] = '0'
	}
	copy(code[len(code)-len(digits):], digits)
	expiry := time.Unix(
		(int64(counter)+1)*int64(payload.Period), 0,
	).UTC()
	return code, expiry, nil
}

func blank(value string) bool {
	return strings.TrimSpace(value) == ""
}

var (
	schemaCredentialList = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"space_id":{"type":"string","description":"Space ID"},
			"type":{"type":"string","description":"Optional credential type filter","enum":["login","api_token","ssh_key","database","totp"]},
			"tags":{"type":"object","description":"Required credential tag key-value filters","additionalProperties":{"type":"string"}},
			"include_deleted":{"type":"boolean","description":"Include credentials in the recycle bin"},
			"deleted_only":{"type":"boolean","description":"Return only credentials in the recycle bin"},
			"after":{"type":"string","description":"Opaque cursor returned by the previous page"},
			"limit":{"type":"integer","description":"Maximum metadata records to return","minimum":1,"maximum":500}
		},"required":["space_id"]
	}`)
	schemaCredentialGet = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"space_id":{"type":"string","description":"Space that bounds authorization"},
			"credential_id":{"type":"string","description":"Credential ID to read"}
		},"required":["space_id","credential_id"]
	}`)
	schemaCredentialCreate = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"space_id":{"type":"string","description":"Space that will own the credential"},
			"display_name":{"type":"string","description":"Human-readable credential name"},
			"type":{"type":"string","description":"Credential payload type","enum":["login","api_token","ssh_key","database","totp"]},
			"tags":{"type":"object","description":"Credential authorization and search tags","additionalProperties":{"type":"string"}},
			"asset_ids":{"type":"array","description":"Assets in the same Space to link","items":{"type":"string"}},
			"payload":{"type":"object","description":"Sensitive credential payload"},
			"reason":{"type":"string","description":"Required human-readable reason recorded in audit"},
			"idempotency_key":{"type":"string","description":"Required unique retry key; reuse only for the identical create"}
		},
		"required":["space_id","display_name","type","payload","reason","idempotency_key"]
	}`)
	schemaCredentialUpdate = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"space_id":{"type":"string","description":"Space that bounds authorization"},
			"credential_id":{"type":"string","description":"Credential ID to update"},
			"expected_version":{"type":"integer","description":"Required current version for optimistic concurrency","minimum":1},
			"display_name":{"type":"string","description":"Replacement human-readable name"},
			"tags":{"type":"object","description":"Replacement authorization and search tags","additionalProperties":{"type":"string"}},
			"asset_ids":{"type":"array","description":"Replacement same-Space asset links","items":{"type":"string"}},
			"payload":{"type":"object","description":"Sensitive replacement credential payload"},
			"reason":{"type":"string","description":"Required human-readable reason recorded in audit"},
			"idempotency_key":{"type":"string","description":"Required unique retry key; reuse only for the identical update"}
		},
		"required":["space_id","credential_id","expected_version","reason","idempotency_key"]
	}`)
	schemaCredentialDelete = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"space_id":{"type":"string","description":"Space that bounds authorization"},
			"credential_id":{"type":"string","description":"Credential ID to move to the recycle bin"},
			"expected_version":{"type":"integer","description":"Required current version for optimistic concurrency","minimum":1},
			"reason":{"type":"string","description":"Required human-readable reason recorded in audit"},
			"idempotency_key":{"type":"string","description":"Required unique retry key; reuse only for the identical delete"}
		},
		"required":["space_id","credential_id","expected_version","reason","idempotency_key"]
	}`)
	schemaTOTPGenerate = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"space_id":{"type":"string","description":"Space that bounds TOTP authorization"},
			"credential_id":{"type":"string","description":"TOTP credential ID used to generate the current code"}
		},"required":["space_id","credential_id"]
	}`)
	schemaAssetList = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"space_id":{"type":"string","description":"Space that bounds authorization"},
			"type":{"type":"string","description":"Optional asset type filter"},
			"environment":{"type":"string","description":"Optional asset environment filter"},
			"status":{"type":"string","description":"Optional asset status filter"},
			"tags":{"type":"object","description":"Required asset tag key-value filters","additionalProperties":{"type":"string"}},
			"after":{"type":"string","description":"Opaque cursor returned by the previous page"},
			"limit":{"type":"integer","description":"Maximum assets to return","minimum":1,"maximum":500}
		},"required":["space_id"]
	}`)
	schemaAssetGet = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"space_id":{"type":"string","description":"Space that bounds authorization"},
			"asset_id":{"type":"string","description":"Asset ID to read"}
		},"required":["space_id","asset_id"]
	}`)
	schemaCredentialMetadataOutput = json.RawMessage(`{
		"type":"object","description":"Credential metadata","additionalProperties":false,
		"properties":{
			"id":{"type":"string","description":"Credential ID"},
			"space_id":{"type":"string","description":"Owning Space ID"},
			"display_name":{"type":"string","description":"Human-readable credential name"},
			"type":{"type":"string","description":"Credential payload type","enum":["login","api_token","ssh_key","database","totp"]},
			"version":{"type":"integer","description":"Current optimistic concurrency version","minimum":1},
			"tags":{"type":"object","description":"Credential authorization and search tags","additionalProperties":{"type":"string"}},
			"asset_ids":{"type":"array","description":"Linked same-Space asset IDs","items":{"type":"string"}},
			"deleted_at":{"type":"string","description":"Recycle-bin timestamp when deleted","format":"date-time"}
		},
		"required":["id","space_id","display_name","type","version","tags","asset_ids"]
	}`)
	schemaCredentialListOutput = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"items":{"type":"array","description":"Credential metadata records; never plaintext payloads","items":` + string(schemaCredentialMetadataOutput) + `},
			"next_cursor":{"type":"string","description":"Opaque cursor for the next page"}
		},"required":["items"]
	}`)
	schemaCredentialGetOutput = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"metadata":` + string(schemaCredentialMetadataOutput) + `,
			"payload":{"type":"object","description":"Sensitive credential payload"}
		},"required":["metadata","payload"]
	}`)
	schemaMutationOutput = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"id":{"type":"string","description":"Mutated credential ID"},
			"version":{"type":"integer","description":"Resulting credential version","minimum":1},
			"status":{"type":"integer","description":"Stable domain HTTP-equivalent status","minimum":200,"maximum":299}
		},"required":["id","version","status"]
	}`)
	schemaDeleteOutput = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"id":{"type":"string","description":"Deleted credential ID"},
			"deleted":{"description":"True when the credential is in the recycle bin","const":true}
		},
		"required":["id","deleted"]
	}`)
	schemaTOTPOutput = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"code":{"type":"string","description":"Sensitive current one-time code; never the seed","pattern":"^[0-9]{6}([0-9]{2})?$"},
			"expiry":{"type":"string","description":"Trusted server time when the code expires","format":"date-time"}
		},"required":["code","expiry"]
	}`)
	schemaAssetOutput = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"id":{"type":"string","description":"Asset ID"},
			"space_id":{"type":"string","description":"Owning Space ID"},
			"name":{"type":"string","description":"Human-readable asset name"},
			"type":{"type":"string","description":"Asset type"},
			"hostname":{"type":"string","description":"Asset hostname"},
			"os":{"type":"string","description":"Operating system"},
			"environment":{"type":"string","description":"Deployment environment"},
			"status":{"type":"string","description":"Operational status"},
			"ips":{"type":"array","description":"Canonical IP addresses","items":{"type":"string"}},
			"ports":{"type":"array","description":"Network ports","items":{"type":"integer","minimum":1,"maximum":65535}},
			"tags":{"type":"object","description":"Asset search and authorization tags","additionalProperties":{"type":"string"}},
			"notes":{"type":"string","description":"Non-secret asset notes"},
			"version":{"type":"integer","description":"Current optimistic concurrency version","minimum":1},
			"created_at":{"type":"string","description":"Creation timestamp","format":"date-time"},
			"updated_at":{"type":"string","description":"Last update timestamp","format":"date-time"},
			"deleted_at":{"type":"string","description":"Deletion timestamp when deleted","format":"date-time"}
		},
		"required":["id","space_id","name","type","hostname","os","environment",
			"status","ips","ports","tags","notes","version","created_at","updated_at"]
	}`)
	schemaAssetListOutput = json.RawMessage(`{
		"type":"object","additionalProperties":false,
		"properties":{
			"items":{"type":"array","description":"Authorized asset records","items":` + string(schemaAssetOutput) + `},
			"next_cursor":{"type":"string","description":"Opaque cursor for the next page"}
		},"required":["items"]
	}`)
)
