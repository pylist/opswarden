package httpapi

import (
	"net/http"

	"opswarden/internal/authorization"
	"opswarden/internal/backup"
)

func (router *Router) handleBackups(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet || router.deps.Backups == nil {
		writeAPIError(
			writer, request, http.StatusNotFound, "NOT_FOUND", false, nil,
		)
		return
	}
	query, err := parseQuery(request, "limit")
	if err != nil {
		writeAPIError(
			writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil,
		)
		return
	}
	limit, err := queryInt(query, "limit")
	if err != nil || limit < 0 || limit > 200 {
		writeAPIError(
			writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil,
		)
		return
	}
	auth, err := router.authorizeSystemHuman(
		request, authorization.ListBackups,
	)
	if err != nil {
		writeSystemAuthorizationError(writer, request, auth, err)
		return
	}
	runs, err := router.deps.Backups.ListRuns(request.Context(), limit)
	if err != nil {
		writeAPIError(
			writer, request, http.StatusServiceUnavailable,
			"STORAGE_UNAVAILABLE", true, nil,
		)
		return
	}
	if err := router.recordAuthentication(
		request.Context(), auth.actor, "backup.list", "backup", "",
	); err != nil {
		writeAPIError(
			writer, request, http.StatusServiceUnavailable,
			"STORAGE_UNAVAILABLE", true, nil,
		)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Items []backup.RunRecord `json:"items"`
	}{Items: runs})
}
