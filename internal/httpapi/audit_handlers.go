package httpapi

import (
	"errors"
	"net/http"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
)

type auditEventResponse struct {
	ID           string             `json:"id"`
	RequestID    string             `json:"requestId"`
	CreatedAt    any                `json:"createdAt"`
	ActorType    audit.ActorType    `json:"actorType"`
	ActorID      string             `json:"actorId"`
	Fingerprint  string             `json:"fingerprint"`
	Action       string             `json:"action"`
	SpaceID      string             `json:"spaceId,omitempty"`
	ResourceType string             `json:"resourceType"`
	ResourceID   string             `json:"resourceId,omitempty"`
	SourceIP     string             `json:"sourceIp"`
	UserAgent    string             `json:"userAgent,omitempty"`
	Success      bool               `json:"success"`
	ErrorCode    string             `json:"errorCode,omitempty"`
	ChangeFields audit.ChangeFields `json:"changeFields"`
	Reason       string             `json:"reason,omitempty"`
}

func (router *Router) handleAudit(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || router.deps.Audit == nil {
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
		return
	}
	auth, ok := request.Context().Value(authenticationKey).(authentication)
	if !ok || auth.human == nil || router.deps.Spaces == nil {
		writeAPIError(writer, request, http.StatusUnauthorized, "UNAUTHENTICATED", false, nil)
		return
	}
	query, err := parseQuery(
		request, "spaceId", "actorType", "actorId", "action",
		"resourceType", "resourceId", "after", "limit",
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
	human, err := router.deps.Spaces.ResolveAuthorizationPrincipal(
		request.Context(), *auth.human, query["spaceId"],
	)
	if err != nil {
		writeDomainError(writer, request, err)
		return
	}
	decision := authorization.DecisionForHuman(
		human,
		authorization.Resource{SpaceID: query["spaceId"]},
		authorization.ListAuditEvents,
	)
	if err := decision.Err(); err != nil {
		if errors.Is(err, authorization.ErrNotFound) {
			writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
		} else {
			writeDomainError(writer, request, err)
		}
		return
	}
	actorType := audit.ActorType(query["actorType"])
	if actorType != "" && actorType != audit.ActorUser &&
		actorType != audit.ActorAgent && actorType != audit.ActorAnonymous &&
		actorType != audit.ActorSystem {
		writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
		return
	}
	events, next, err := router.deps.Audit.List(
		request.Context(), audit.Filter{
			SpaceID: query["spaceId"], ActorType: actorType,
			ActorID: query["actorId"], Action: query["action"],
			ResourceType: query["resourceType"], ResourceID: query["resourceId"],
			After: audit.Cursor(query["after"]), Limit: limit,
		},
	)
	if err != nil {
		writeDomainError(writer, request, err)
		return
	}
	response := make([]auditEventResponse, 0, len(events))
	for _, event := range events {
		response = append(response, auditEventResponse{
			ID: event.ID, RequestID: event.RequestID, CreatedAt: event.CreatedAt,
			ActorType: event.Actor.Type, ActorID: event.Actor.ID,
			Fingerprint: event.Actor.Fingerprint, Action: event.Action,
			SpaceID: event.SpaceID, ResourceType: event.ResourceType,
			ResourceID: event.ResourceID, SourceIP: event.SourceIP,
			UserAgent: event.UserAgent, Success: event.Success,
			ErrorCode: event.ErrorCode, ChangeFields: event.ChangeFields,
			Reason: event.Reason,
		})
	}
	writeJSON(writer, http.StatusOK, struct {
		Items      []auditEventResponse `json:"items"`
		NextCursor audit.Cursor         `json:"nextCursor,omitempty"`
	}{Items: response, NextCursor: next})
}
