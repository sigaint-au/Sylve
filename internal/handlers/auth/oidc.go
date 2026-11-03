// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2026 The FreeBSD Foundation.

package authHandlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/alchemillahq/sylve/internal"
	"github.com/alchemillahq/sylve/internal/config"
	"github.com/alchemillahq/sylve/internal/services/auth"
	"github.com/gin-gonic/gin"
)

type BeginOIDCLoginRequest struct {
	Remember bool `json:"remember"`
}

type BeginOIDCLoginResponse struct {
	AuthURL string `json:"authUrl"`
}

type FinishOIDCLoginRequest struct {
	Code  string `json:"code" binding:"required,max=8192"`
	State string `json:"state" binding:"required,max=128"`
}

func writeOIDCLoginError(c *gin.Context, err error) {
	status := http.StatusInternalServerError
	code := "internal_server_error"
	switch err.Error() {
	case "oidc_auth_disabled":
		status, code = http.StatusForbidden, "oidc_auth_disabled"
	case "invalid_oidc_redirect_uri", "invalid_oidc_request", "challenge_not_found", "challenge_used", "challenge_expired":
		status, code = http.StatusBadRequest, "invalid_oidc_request"
	case "invalid_credentials":
		status, code = http.StatusUnauthorized, "invalid_credentials"
	case "user_not_registered_in_sylve", "only_admin_allowed", "account_locked":
		status, code = http.StatusForbidden, err.Error()
	case "user_source_conflict":
		status, code = http.StatusConflict, "user_source_conflict"
	case "oidc_provider_unavailable":
		status, code = http.StatusServiceUnavailable, "authentication_service_unavailable"
	case "oidc_ca_file_unreadable", "oidc_ca_file_invalid", "invalid_oidc_issuer", "oidc_issuer_mismatch", "invalid_oidc_endpoint":
		status, code = http.StatusServiceUnavailable, "authentication_service_unavailable"
	}
	writeAuthCodeError(c, status, code)
}

// @Summary Begin OIDC login
// @Description Create an OIDC authorization URL using Authorization Code with PKCE
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body BeginOIDCLoginRequest true "OIDC login options"
// @Success 200 {object} internal.APIResponse[BeginOIDCLoginResponse] "Success"
// @Failure 400 {object} internal.APIResponse[any] "Bad Request"
// @Failure 403 {object} internal.APIResponse[any] "Forbidden"
// @Failure 413 {object} internal.APIResponse[any] "Request Entity Too Large"
// @Failure 503 {object} internal.APIResponse[any] "Service Unavailable"
// @Router /auth/oidc/login/begin [post]
func BeginOIDCLoginHandler(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		setSensitiveAuthResponseHeaders(c)
		var request BeginOIDCLoginRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				writeAuthCodeError(c, http.StatusRequestEntityTooLarge, "request_body_too_large")
			} else {
				writeAuthCodeError(c, http.StatusBadRequest, "invalid_request_payload")
			}
			return
		}

		redirectURI := config.GetOIDCConfig().RedirectURL
		if strings.TrimSpace(redirectURI) == "" {
			_, origin, err := getPasskeyRelyingParty(c)
			if err != nil {
				writeAuthCodeError(c, http.StatusBadRequest, "oidc_requires_https")
				return
			}
			redirectURI = strings.TrimRight(origin, "/") + "/"
		}
		authURL, err := authService.BeginOIDCLogin(c.Request.Context(), redirectURI, request.Remember)
		if err != nil {
			writeOIDCLoginError(c, err)
			return
		}
		c.JSON(http.StatusOK, internal.APIResponse[BeginOIDCLoginResponse]{
			Status: "success", Message: "oidc_login_started",
			Data: BeginOIDCLoginResponse{AuthURL: authURL},
		})
	}
}

// @Summary Finish OIDC login
// @Description Validate the OIDC authorization response and create a Sylve session
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body FinishOIDCLoginRequest true "OIDC callback"
// @Success 200 {object} internal.APIResponse[SuccessfulLogin] "Success"
// @Failure 400 {object} internal.APIResponse[any] "Bad Request"
// @Failure 401 {object} internal.APIResponse[any] "Unauthorized"
// @Failure 403 {object} internal.APIResponse[any] "Forbidden"
// @Failure 409 {object} internal.APIResponse[any] "Conflict"
// @Failure 413 {object} internal.APIResponse[any] "Request Entity Too Large"
// @Failure 503 {object} internal.APIResponse[any] "Service Unavailable"
// @Router /auth/oidc/login/finish [post]
func FinishOIDCLoginHandler(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		setSensitiveAuthResponseHeaders(c)
		var request FinishOIDCLoginRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				writeAuthCodeError(c, http.StatusRequestEntityTooLarge, "request_body_too_large")
			} else {
				writeAuthCodeError(c, http.StatusBadRequest, "invalid_request_payload")
			}
			return
		}

		user, token, err := authService.FinishOIDCLogin(c.Request.Context(), request.Code, request.State)
		if err != nil {
			writeOIDCLoginError(c, err)
			return
		}
		completeLogin(c, authService, user.ID, token)
	}
}
