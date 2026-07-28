package httpapi

import (
	"net/http"

	"opswarden/internal/authorization"
)

func (router *Router) handleLiveness(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" ||
		router.deps.Health == nil {
		writeAPIError(
			writer, request, http.StatusNotFound, "NOT_FOUND", false, nil,
		)
		return
	}
	writeJSON(writer, http.StatusOK, router.deps.Health.Liveness())
}

func (router *Router) handleDetailedHealth(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" ||
		router.deps.Health == nil {
		writeAPIError(
			writer, request, http.StatusNotFound, "NOT_FOUND", false, nil,
		)
		return
	}
	auth, err := router.authorizeSystemHuman(
		request, authorization.ReadHealth,
	)
	if err != nil {
		writeSystemAuthorizationError(writer, request, auth, err)
		return
	}
	detail, err := router.deps.Health.Detailed(request.Context())
	if err != nil {
		writeAPIError(
			writer, request, http.StatusServiceUnavailable,
			"STORAGE_UNAVAILABLE", true, nil,
		)
		return
	}
	if err := router.recordAuthentication(
		request.Context(), auth.actor, "health.read", "health", "",
	); err != nil {
		writeAPIError(
			writer, request, http.StatusServiceUnavailable,
			"STORAGE_UNAVAILABLE", true, nil,
		)
		return
	}
	writeJSON(writer, http.StatusOK, detail)
}

func (router *Router) authorizeSystemHuman(
	request *http.Request,
	action authorization.Action,
) (authentication, error) {
	auth, ok := request.Context().Value(authenticationKey).(authentication)
	if !ok || auth.human == nil || router.deps.Spaces == nil {
		return auth, authorization.ErrUnauthenticated
	}
	principal, err := router.deps.Spaces.ResolveAuthorizationPrincipal(
		request.Context(), *auth.human, "",
	)
	if err != nil {
		return auth, err
	}
	return auth, authorization.DecisionForHuman(
		principal, authorization.Resource{}, action,
	).Err()
}

func writeSystemAuthorizationError(
	writer http.ResponseWriter,
	request *http.Request,
	auth authentication,
	err error,
) {
	if auth.agent != nil {
		writeAPIError(
			writer, request, http.StatusNotFound, "NOT_FOUND", false, nil,
		)
		return
	}
	if auth.human == nil {
		writeAPIError(
			writer, request, http.StatusUnauthorized,
			"UNAUTHENTICATED", false, nil,
		)
		return
	}
	writeDomainError(writer, request, err)
}
