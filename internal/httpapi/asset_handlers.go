package httpapi

import (
	"net/http"
	"net/netip"

	"opswarden/internal/assets"
)

type assetCreateRequest struct {
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
}

type assetUpdateRequest struct {
	ExpectedVersion uint64            `json:"expectedVersion"`
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Hostname        string            `json:"hostname"`
	OS              string            `json:"os"`
	Environment     string            `json:"environment"`
	Status          string            `json:"status"`
	IPs             []netip.Addr      `json:"ips"`
	Ports           []uint16          `json:"ports"`
	Tags            map[string]string `json:"tags"`
	Notes           string            `json:"notes"`
}

type assetDeleteRequest struct {
	AssetID         string `json:"assetId"`
	ExpectedVersion uint64 `json:"expectedVersion"`
}

type assetResponse struct {
	ID          string            `json:"id"`
	SpaceID     string            `json:"spaceId"`
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
	CreatedAt   any               `json:"createdAt"`
	UpdatedAt   any               `json:"updatedAt"`
	DeletedAt   any               `json:"deletedAt,omitempty"`
}

func (router *Router) handleAssets(
	writer http.ResponseWriter,
	request *http.Request,
	spaceID string,
	rest []string,
) {
	if router.deps.Assets == nil {
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
			request, "type", "environment", "status", "after", "limit",
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
		items, next, err := router.deps.Assets.List(
			request.Context(), principal, assets.ListFilter{
				SpaceID: spaceID, Type: query["type"],
				Environment: query["environment"], Status: query["status"],
				After: query["after"], Limit: limit,
			},
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		response := make([]assetResponse, 0, len(items))
		for _, item := range items {
			response = append(response, assetDTO(item))
		}
		writeJSON(writer, http.StatusOK, struct {
			Items      []assetResponse `json:"items"`
			NextCursor string          `json:"nextCursor,omitempty"`
		}{Items: response, NextCursor: next})
	case len(rest) == 0 && request.Method == http.MethodPost:
		if principal.Agent != nil {
			writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
			return
		}
		var input assetCreateRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		asset, err := router.deps.Assets.Create(
			request.Context(), principal, assets.CreateInput{
				SpaceID: spaceID, Name: input.Name, Type: input.Type,
				Hostname: input.Hostname, OS: input.OS,
				Environment: input.Environment, Status: input.Status,
				IPs: input.IPs, Ports: input.Ports, Tags: input.Tags,
				Notes: input.Notes,
			},
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusCreated, assetDTO(asset))
	case len(rest) == 1 && rest[0] != "" && request.Method == http.MethodGet:
		asset, err := router.deps.Assets.Get(request.Context(), principal, rest[0])
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		if asset.SpaceID != spaceID {
			writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
			return
		}
		writeJSON(writer, http.StatusOK, assetDTO(asset))
	case len(rest) == 2 && rest[0] != "" && rest[1] == "credentials" &&
		request.Method == http.MethodGet:
		query, err := parseQuery(request, "after", "limit")
		if err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		limit, err := queryInt(query, "limit")
		if err != nil {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		items, next, err := router.deps.Assets.ListCredentialMetadata(
			request.Context(), principal, rest[0],
			assets.CredentialListPage{After: query["after"], Limit: limit},
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
	case len(rest) == 1 && rest[0] != "" && request.Method == http.MethodPut:
		if principal.Agent != nil {
			writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
			return
		}
		var input assetUpdateRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil || input.ExpectedVersion == 0 {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		asset, err := router.deps.Assets.Update(
			request.Context(), principal, assets.UpdateInput{
				AssetID: rest[0], ExpectedVersion: input.ExpectedVersion,
				Name: input.Name, Type: input.Type, Hostname: input.Hostname,
				OS: input.OS, Environment: input.Environment, Status: input.Status,
				IPs: input.IPs, Ports: input.Ports, Tags: input.Tags, Notes: input.Notes,
			},
		)
		if err != nil {
			writeDomainError(writer, request, err)
			return
		}
		if asset.SpaceID != spaceID {
			writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
			return
		}
		writeJSON(writer, http.StatusOK, assetDTO(asset))
	case len(rest) == 1 && rest[0] != "" && request.Method == http.MethodDelete:
		if principal.Agent != nil {
			writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
			return
		}
		var input assetDeleteRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil || input.AssetID != rest[0] || input.ExpectedVersion == 0 {
			writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
			return
		}
		if err := router.deps.Assets.Delete(
			request.Context(), principal, rest[0], input.ExpectedVersion,
		); err != nil {
			writeDomainError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
	}
}

func assetDTO(asset assets.Asset) assetResponse {
	response := assetResponse{
		ID: asset.ID, SpaceID: asset.SpaceID, Name: asset.Name, Type: asset.Type,
		Hostname: asset.Hostname, OS: asset.OS, Environment: asset.Environment,
		Status: asset.Status, IPs: asset.IPs, Ports: asset.Ports, Tags: asset.Tags,
		Notes: asset.Notes, Version: asset.Version,
		CreatedAt: asset.CreatedAt, UpdatedAt: asset.UpdatedAt,
	}
	if asset.DeletedAt != nil {
		response.DeletedAt = asset.DeletedAt
	}
	return response
}
