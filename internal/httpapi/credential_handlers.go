package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"opswarden/internal/credentials"
	"opswarden/internal/identity"
	"opswarden/internal/spaces"
)

type credentialCreateRequest struct {
	DisplayName string            `json:"displayName"`
	Type        credentials.Type  `json:"type"`
	Tags        map[string]string `json:"tags"`
	AssetIDs    []string          `json:"assetIds"`
	Payload     json.RawMessage   `json:"payload"`
}

type credentialUpdateRequest struct {
	ExpectedVersion uint64            `json:"expectedVersion"`
	DisplayName     *string           `json:"displayName,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	AssetIDs        []string          `json:"assetIds,omitempty"`
	Payload         json.RawMessage   `json:"payload,omitempty"`
}

type credentialDeleteRequest struct {
	CredentialID    string `json:"credentialId"`
	ExpectedVersion uint64 `json:"expectedVersion"`
}

type credentialRestoreRequest struct {
	ExpectedVersion uint64 `json:"expectedVersion"`
}

type credentialMetadataResponse struct {
	ID          string            `json:"id"`
	SpaceID     string            `json:"spaceId"`
	DisplayName string            `json:"displayName"`
	Type        credentials.Type  `json:"type"`
	Version     uint64            `json:"version"`
	Tags        map[string]string `json:"tags"`
	AssetIDs    []string          `json:"assetIds"`
	DeletedAt   any               `json:"deletedAt,omitempty"`
}

type spaceResponse struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Role      spaces.Role `json:"role"`
	CreatedAt any         `json:"createdAt,omitempty"`
	UpdatedAt any         `json:"updatedAt,omitempty"`
}

type mutationResponse struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

type memberCreateRequest struct {
	UserID string      `json:"userId"`
	Role   spaces.Role `json:"role"`
}

type memberRoleRequest struct {
	Role            spaces.Role `json:"role"`
	ExpectedVersion uint64      `json:"expectedVersion"`
}

type memberDeleteRequest struct {
	ExpectedVersion uint64 `json:"expectedVersion"`
}

type memberResponse struct {
	UserID    string      `json:"userId"`
	Email     string      `json:"email"`
	Role      spaces.Role `json:"role"`
	Version   uint64      `json:"version"`
	CreatedAt any         `json:"createdAt"`
}

func (router *Router) handleSpaces(writer http.ResponseWriter, request *http.Request) {
	auth, ok := request.Context().Value(authenticationKey).(authentication)
	if !ok || auth.human == nil || router.deps.Spaces == nil {
		writeAPIError(
			writer, request, http.StatusUnauthorized,
			"UNAUTHENTICATED", false, nil,
		)
		return
	}
	switch request.Method {
	case http.MethodGet:
		if request.URL.RawQuery != "" {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		items, err := router.deps.Spaces.ListForUser(request.Context(), *auth.human)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		response := make([]spaceResponse, 0, len(items))
		for _, item := range items {
			response = append(response, spaceDTO(item))
		}
		writeJSON(writer, http.StatusOK, struct {
			Items []spaceResponse `json:"items"`
		}{Items: response})
	case http.MethodPost:
		var input spaces.CreateInput
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		metadata := requestMetadataFromContext(request.Context())
		space, err := router.deps.Spaces.CreateAudited(
			request.Context(), spaces.MutationContext{
				Session: *auth.human, Actor: auth.actor,
				RequestID: metadata.requestID, SourceIP: metadata.sourceIP,
				UserAgent: metadata.userAgent,
			}, input,
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusCreated, spaceDTO(space))
	default:
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
	}
}

func (router *Router) handleSpaceResource(
	writer http.ResponseWriter,
	request *http.Request,
) {
	segments := pathSegments(request.URL.Path)
	if len(segments) < 5 || len(segments) > 7 ||
		segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "spaces" || segments[3] == "" {
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
		return
	}
	spaceID := segments[3]
	switch segments[4] {
	case "credentials":
		router.handleCredentials(writer, request, spaceID, segments[5:])
	case "assets":
		router.handleAssets(writer, request, spaceID, segments[5:])
	case "members":
		router.handleMembers(writer, request, spaceID, segments[5:])
	default:
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
	}
}

func (router *Router) handleMembers(
	writer http.ResponseWriter,
	request *http.Request,
	spaceID string,
	rest []string,
) {
	if router.deps.Spaces == nil {
		writeAPIError(writer, request, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", true, nil)
		return
	}
	auth, ok := request.Context().Value(authenticationKey).(authentication)
	if !ok || auth.human == nil {
		writeAPIError(writer, request, http.StatusUnauthorized, "UNAUTHENTICATED", false, nil)
		return
	}
	mutation := router.spaceMutationContext(request, *auth.human)
	switch {
	case len(rest) == 0 && request.Method == http.MethodGet:
		members, err := router.deps.Spaces.ListMembers(
			request.Context(), *auth.human, spaceID,
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		response := make([]memberResponse, 0, len(members))
		for _, member := range members {
			response = append(response, memberDTO(member))
		}
		writeJSON(writer, http.StatusOK, struct {
			Items []memberResponse `json:"items"`
		}{Items: response})
	case len(rest) == 0 && request.Method == http.MethodPost:
		var input memberCreateRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		member, err := router.deps.Spaces.AddMemberAudited(
			request.Context(), mutation, spaceID, input.UserID, input.Role,
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusCreated, memberDTO(member))
	case len(rest) == 1 && rest[0] != "" && request.Method == http.MethodPatch:
		var input memberRoleRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		if input.ExpectedVersion == 0 {
			writeAPIError(
				writer, request, http.StatusBadRequest,
				"INVALID_REQUEST", false, nil,
			)
			return
		}
		member, err := router.deps.Spaces.ChangeRoleAudited(
			request.Context(), mutation, spaceID, rest[0],
			input.Role, input.ExpectedVersion,
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusOK, memberDTO(member))
	case len(rest) == 1 && rest[0] != "" && request.Method == http.MethodDelete:
		var input memberDeleteRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		if input.ExpectedVersion == 0 {
			writeAPIError(
				writer, request, http.StatusBadRequest,
				"INVALID_REQUEST", false, nil,
			)
			return
		}
		if err := router.deps.Spaces.RemoveMemberAudited(
			request.Context(), mutation, spaceID, rest[0], input.ExpectedVersion,
		); err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
	}
}

func (router *Router) spaceMutationContext(
	request *http.Request,
	session identity.SessionPrincipal,
) spaces.MutationContext {
	auth, _ := request.Context().Value(authenticationKey).(authentication)
	metadata := requestMetadataFromContext(request.Context())
	return spaces.MutationContext{
		Session: session, Actor: auth.actor, RequestID: metadata.requestID,
		SourceIP: metadata.sourceIP, UserAgent: metadata.userAgent,
	}
}

func memberDTO(member spaces.Member) memberResponse {
	return memberResponse{
		UserID: member.UserID, Email: member.Email, Role: member.Role,
		Version: member.Version, CreatedAt: member.CreatedAt,
	}
}

func (router *Router) handleCredentials(
	writer http.ResponseWriter,
	request *http.Request,
	spaceID string,
	rest []string,
) {
	if router.deps.Credentials == nil {
		writeAPIError(writer, request, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", true, nil)
		return
	}
	principal, err := router.principal(request.Context(), spaceID)
	if err != nil {
		writeDomainError(writer, request, err)
		return
	}
	switch {
	case len(rest) == 0 && request.Method == http.MethodGet:
		query, err := parseQuery(
			request, "type", "after", "limit", "includeDeleted", "deletedOnly",
		)
		if err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		limit, err := queryInt(query, "limit")
		if err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		includeDeleted, err := queryBool(query, "includeDeleted")
		if err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		deletedOnly, err := queryBool(query, "deletedOnly")
		if err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		items, next, err := router.deps.Credentials.List(
			request.Context(), principal, credentials.ListFilter{
				SpaceID: spaceID, Type: credentials.Type(query["type"]),
				After: query["after"], Limit: limit,
				IncludeDeleted: includeDeleted, DeletedOnly: deletedOnly,
			},
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		response := make([]credentialMetadataResponse, 0, len(items))
		for _, item := range items {
			response = append(response, credentialMetadataDTO(item))
		}
		writeJSON(writer, http.StatusOK, struct {
			Items      []credentialMetadataResponse `json:"items"`
			NextCursor string                       `json:"nextCursor,omitempty"`
		}{Items: response, NextCursor: next})
	case len(rest) == 0 && request.Method == http.MethodPost:
		var input credentialCreateRequest
		if err := decodeJSONBody(
			writer, request, credentialBodyLimit, &input,
		); err != nil {
			router.rejectInvalidCredential(
				writer, request, principal, credentials.OperationCreate,
			)
			return
		}
		writeContext, ok := credentialWriteContext(request, principal)
		if !ok {
			router.rejectInvalidCredential(
				writer, request, principal, credentials.OperationCreate,
			)
			return
		}
		result, err := router.deps.Credentials.Create(
			request.Context(), principal, credentials.CreateInput{
				SpaceID: spaceID, DisplayName: input.DisplayName, Type: input.Type,
				Tags: input.Tags, AssetIDs: input.AssetIDs, Payload: input.Payload,
			}, writeContext,
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writeJSON(writer, result.Status, mutationResponse{
			ID: result.ID, Version: result.Version,
		})
	case len(rest) == 1 && rest[0] != "" && request.Method == http.MethodGet:
		decrypted, err := router.deps.Credentials.Get(
			request.Context(), principal, rest[0],
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		if decrypted.Metadata.SpaceID != spaceID {
			clear(decrypted.Payload)
			writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
			return
		}
		writeJSON(writer, http.StatusOK, struct {
			Metadata credentialMetadataResponse `json:"metadata"`
			Payload  json.RawMessage            `json:"payload"`
		}{
			Metadata: credentialMetadataDTO(decrypted.Metadata),
			Payload:  decrypted.Payload,
		})
		clear(decrypted.Payload)
	case len(rest) == 1 && rest[0] != "" && request.Method == http.MethodPatch:
		var input credentialUpdateRequest
		if err := decodeJSONBody(
			writer, request, credentialBodyLimit, &input,
		); err != nil || input.ExpectedVersion == 0 {
			router.rejectInvalidCredential(
				writer, request, principal, credentials.OperationUpdate,
			)
			return
		}
		writeContext, ok := credentialWriteContext(request, principal)
		if !ok {
			router.rejectInvalidCredential(
				writer, request, principal, credentials.OperationUpdate,
			)
			return
		}
		result, err := router.deps.Credentials.Update(
			request.Context(), principal, credentials.UpdateInput{
				CredentialID: rest[0], ExpectedVersion: input.ExpectedVersion,
				DisplayName: input.DisplayName, Tags: input.Tags,
				AssetIDs: input.AssetIDs, Payload: input.Payload,
			}, writeContext,
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writeJSON(writer, result.Status, mutationResponse{
			ID: result.ID, Version: result.Version,
		})
	case len(rest) == 1 && rest[0] != "" && request.Method == http.MethodDelete:
		var input credentialDeleteRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil || input.CredentialID != rest[0] || input.ExpectedVersion == 0 {
			router.rejectInvalidCredential(
				writer, request, principal, credentials.OperationDelete,
			)
			return
		}
		writeContext, ok := credentialWriteContext(request, principal)
		if !ok {
			router.rejectInvalidCredential(
				writer, request, principal, credentials.OperationDelete,
			)
			return
		}
		if err := router.deps.Credentials.Delete(
			request.Context(), principal, rest[0], input.ExpectedVersion, writeContext,
		); err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	case len(rest) == 2 && rest[0] != "" && rest[1] == "restore" &&
		request.Method == http.MethodPost:
		if principal.Agent != nil {
			router.rejectConcealedCredential(
				writer, request, principal, credentials.OperationRestore,
			)
			return
		}
		var input credentialRestoreRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil || input.ExpectedVersion == 0 {
			router.rejectInvalidCredential(
				writer, request, principal, credentials.OperationRestore,
			)
			return
		}
		writeContext, _ := credentialWriteContext(request, principal)
		metadata, err := router.deps.Credentials.Restore(
			request.Context(), principal, rest[0], input.ExpectedVersion, writeContext,
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		if metadata.SpaceID != spaceID {
			writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
			return
		}
		writeJSON(writer, http.StatusOK, credentialMetadataDTO(metadata))
	case len(rest) == 2 && rest[0] != "" && rest[1] == "purge" &&
		request.Method == http.MethodPost:
		if principal.Agent != nil {
			router.rejectConcealedCredential(
				writer, request, principal, credentials.OperationPurge,
			)
			return
		}
		var input credentialRestoreRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil || input.ExpectedVersion == 0 {
			router.rejectInvalidCredential(
				writer, request, principal, credentials.OperationPurge,
			)
			return
		}
		writeContext, _ := credentialWriteContext(request, principal)
		if err := router.deps.Credentials.Purge(
			request.Context(), principal, spaceID, rest[0],
			input.ExpectedVersion, writeContext,
		); err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
	}
}

func (router *Router) rejectConcealedCredential(
	writer http.ResponseWriter,
	request *http.Request,
	principal credentials.Principal,
	operation credentials.Operation,
) {
	if err := router.deps.Credentials.RecordConcealedAttempt(
		request.Context(), principal, operation,
	); err != nil {
		writeAPIError(
			writer, request, http.StatusServiceUnavailable,
			"STORAGE_UNAVAILABLE", true, nil,
		)
		return
	}
	writeAPIError(
		writer, request, http.StatusNotFound, "NOT_FOUND", false, nil,
	)
}

func (router *Router) rejectInvalidCredential(
	writer http.ResponseWriter,
	request *http.Request,
	principal credentials.Principal,
	operation credentials.Operation,
) {
	if err := router.deps.Credentials.RecordInvalidAttempt(
		request.Context(), principal, operation,
	); err != nil {
		writeAPIError(
			writer, request, http.StatusServiceUnavailable,
			"STORAGE_UNAVAILABLE", true, nil,
		)
		return
	}
	writeAPIError(
		writer, request, http.StatusBadRequest,
		"INVALID_REQUEST", false, nil,
	)
}

func credentialWriteContext(
	request *http.Request,
	principal credentials.Principal,
) (credentials.WriteContext, bool) {
	context := credentials.WriteContext{Actor: principal.Actor}
	if principal.Agent == nil {
		return context, true
	}
	idempotencyValues := request.Header.Values("Idempotency-Key")
	if len(idempotencyValues) != 1 ||
		idempotencyValues[0] == "" ||
		len(idempotencyValues[0]) > 256 {
		return credentials.WriteContext{}, false
	}
	primaryReasons := request.Header.Values("X-OpsWarden-Reason")
	legacyReasons := request.Header.Values("X-Reason")
	if len(primaryReasons) > 1 || len(legacyReasons) > 1 ||
		(len(primaryReasons) == 1 && len(legacyReasons) == 1) {
		return credentials.WriteContext{}, false
	}
	reason := ""
	if len(primaryReasons) == 1 {
		reason = primaryReasons[0]
	} else if len(legacyReasons) == 1 {
		reason = legacyReasons[0]
	}
	if reason == "" {
		return credentials.WriteContext{}, false
	}
	context.IdempotencyKey = idempotencyValues[0]
	context.Reason = reason
	return context, true
}

func credentialMetadataDTO(metadata credentials.Metadata) credentialMetadataResponse {
	response := credentialMetadataResponse{
		ID: metadata.ID, SpaceID: metadata.SpaceID,
		DisplayName: metadata.DisplayName, Type: metadata.Type,
		Version: metadata.Version, Tags: metadata.Tags, AssetIDs: metadata.AssetIDs,
	}
	if metadata.DeletedAt != nil {
		response.DeletedAt = metadata.DeletedAt
	}
	return response
}

func spaceDTO(space spaces.Space) spaceResponse {
	return spaceResponse{
		ID: space.ID, Name: space.Name, Role: space.Role,
		CreatedAt: space.CreatedAt, UpdatedAt: space.UpdatedAt,
	}
}

func parseExpectedVersion(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	return strconv.ParseUint(value, 10, 64)
}
