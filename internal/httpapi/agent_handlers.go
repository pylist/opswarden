package httpapi

import (
	"net/http"

	"opswarden/internal/agents"
	"opswarden/internal/authorization"
	"opswarden/internal/identity"
)

type createAgentRequest struct {
	Name string `json:"name"`
}

type issueAgentTokenRequest struct {
	ExpiresAt string `json:"expiresAt,omitempty"`
}

type setAgentGrantRequest struct {
	SpaceID        string                `json:"spaceId"`
	Scopes         []authorization.Scope `json:"scopes"`
	RequiredLabels map[string]string     `json:"requiredLabels"`
}

type agentResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt any    `json:"createdAt"`
	UpdatedAt any    `json:"updatedAt"`
}

type agentUsageResponse struct {
	AgentID      string `json:"agentId"`
	Name         string `json:"name"`
	TokenCount   int    `json:"tokenCount"`
	ActiveTokens int    `json:"activeTokens"`
	LastUsedAt   any    `json:"lastUsedAt,omitempty"`
}

type issuedTokenResponse struct {
	ID        string `json:"id"`
	Prefix    string `json:"prefix"`
	Token     string `json:"token"`
	ExpiresAt any    `json:"expiresAt,omitempty"`
}

func (router *Router) handleAgents(writer http.ResponseWriter, request *http.Request) {
	if router.deps.Agents == nil {
		writeAPIError(writer, request, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", true, nil)
		return
	}
	auth, ok := request.Context().Value(authenticationKey).(authentication)
	if !ok || auth.human == nil {
		writeAPIError(writer, request, http.StatusUnauthorized, "UNAUTHENTICATED", false, nil)
		return
	}
	mutation := router.agentMutationContext(request, *auth.human)
	segments := pathSegments(request.URL.Path)
	switch {
	case len(segments) == 3 && request.Method == http.MethodGet:
		if request.URL.RawQuery != "" {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		usage, err := router.deps.Agents.ListUsage(request.Context(), mutation)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		response := make([]agentUsageResponse, 0, len(usage))
		for _, item := range usage {
			entry := agentUsageResponse{
				AgentID: item.AgentID, Name: item.Name,
				TokenCount: item.TokenCount, ActiveTokens: item.ActiveTokens,
			}
			if item.LastUsedAt != nil {
				entry.LastUsedAt = item.LastUsedAt
			}
			response = append(response, entry)
		}
		writeJSON(writer, http.StatusOK, struct {
			Items []agentUsageResponse `json:"items"`
		}{Items: response})
	case len(segments) == 3 && request.Method == http.MethodPost:
		if !requireIdempotencyHeader(request) {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		var input createAgentRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		agent, err := router.deps.Agents.Create(
			request.Context(), mutation, agents.CreateInput{Name: input.Name},
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusCreated, agentResponse{
			ID: agent.ID, Name: agent.Name,
			CreatedAt: agent.CreatedAt, UpdatedAt: agent.UpdatedAt,
		})
	case len(segments) == 5 && segments[3] != "" &&
		segments[4] == "tokens" && request.Method == http.MethodPost:
		if !requireIdempotencyHeader(request) {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		var input issueAgentTokenRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		expiry, err := parseRFC3339(input.ExpiresAt)
		if err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		token, err := router.deps.Agents.IssueToken(
			request.Context(), mutation, segments[3], expiry,
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		response := issuedTokenResponse{
			ID: token.ID, Prefix: token.Prefix, Token: token.Raw,
		}
		if !token.ExpiresAt.IsZero() {
			response.ExpiresAt = token.ExpiresAt
		}
		writeJSON(writer, http.StatusCreated, response)
	case len(segments) == 6 && segments[3] != "" &&
		segments[4] == "tokens" && segments[5] != "" &&
		request.Method == http.MethodDelete:
		if !requireIdempotencyHeader(request) {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		if err := router.deps.Agents.RevokeToken(
			request.Context(), mutation, segments[5],
		); err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	case len(segments) == 5 && segments[3] != "" &&
		segments[4] == "grants" && request.Method == http.MethodPut:
		if !requireIdempotencyHeader(request) {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		var input setAgentGrantRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		if err := router.deps.Agents.SetGrant(
			request.Context(), mutation, segments[3], agents.Grant{
				SpaceID: input.SpaceID, Scopes: input.Scopes,
				RequiredLabels: input.RequiredLabels,
			},
		); err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
	}
}

func (router *Router) agentMutationContext(
	request *http.Request,
	session identity.SessionPrincipal,
) agents.MutationContext {
	auth, _ := request.Context().Value(authenticationKey).(authentication)
	metadata := requestMetadataFromContext(request.Context())
	return agents.MutationContext{
		Session: session, Actor: auth.actor, RequestID: metadata.requestID,
		SourceIP: metadata.sourceIP, UserAgent: metadata.userAgent,
	}
}

func requireIdempotencyHeader(request *http.Request) bool {
	values := request.Header.Values("Idempotency-Key")
	return len(values) == 1 && values[0] != "" && len(values[0]) <= 256
}
