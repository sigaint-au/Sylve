// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2026 The FreeBSD Foundation.

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/alchemillahq/sylve/internal"
	"github.com/alchemillahq/sylve/internal/config"
	"github.com/alchemillahq/sylve/internal/db/models"
	clusterModels "github.com/alchemillahq/sylve/internal/db/models/cluster"
	"github.com/golang-jwt/jwt/v5"
)

type mockOIDCProvider struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	mu         sync.RWMutex
	nonce      string
	challenge  string
	claims     map[string]any
	userInfo   map[string]any
}

func newMockOIDCProvider(t *testing.T) *mockOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test signing key: %v", err)
	}
	mock := &mockOIDCProvider{privateKey: key, claims: map[string]any{}, userInfo: map[string]any{}}
	mock.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 mock.server.URL,
				"authorization_endpoint": mock.server.URL + "/authorize",
				"token_endpoint":         mock.server.URL + "/token",
				"jwks_uri":               mock.server.URL + "/jwks",
				"userinfo_endpoint":      mock.server.URL + "/userinfo",
			})
		case "/jwks":
			modulus := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
			exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key", "n": modulus, "e": exponent,
			}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if username, password, ok := r.BasicAuth(); !ok || username != "test-client" || password != "test-secret" {
				http.Error(w, "bad client auth", http.StatusUnauthorized)
				return
			}
			verifierHash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			mock.mu.RLock()
			wantChallenge := mock.challenge
			mock.mu.RUnlock()
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") == "" || base64.RawURLEncoding.EncodeToString(verifierHash[:]) != wantChallenge || r.Form.Get("redirect_uri") != "https://sylve.example/" {
				http.Error(w, "bad exchange", http.StatusBadRequest)
				return
			}
			mock.mu.RLock()
			nonce := mock.nonce
			claims := make(map[string]any, len(mock.claims))
			for name, value := range mock.claims {
				claims[name] = value
			}
			mock.mu.RUnlock()
			claims["iss"] = mock.server.URL
			if _, exists := claims["sub"]; !exists {
				claims["sub"] = "subject-1"
			}
			claims["aud"] = "test-client"
			claims["iat"] = time.Now().Unix()
			claims["exp"] = time.Now().Add(5 * time.Minute).Unix()
			claims["nonce"] = nonce
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
			token.Header["kid"] = "test-key"
			signed, err := token.SignedString(key)
			if err != nil {
				http.Error(w, "sign failed", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "test-access-token", "id_token": signed})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer test-access-token" {
				http.Error(w, "bad access token", http.StatusUnauthorized)
				return
			}
			mock.mu.RLock()
			info := make(map[string]any, len(mock.userInfo))
			for name, value := range mock.userInfo {
				info[name] = value
			}
			mock.mu.RUnlock()
			if _, exists := info["sub"]; !exists {
				info["sub"] = "subject-1"
			}
			_ = json.NewEncoder(w).Encode(info)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(mock.server.Close)
	return mock
}

func (m *mockOIDCProvider) setClaims(claims map[string]any) {
	m.mu.Lock()
	m.claims = claims
	m.mu.Unlock()
}

func (m *mockOIDCProvider) setUserInfo(claims map[string]any) {
	m.mu.Lock()
	m.userInfo = claims
	m.mu.Unlock()
}

func newOIDCTestService(t *testing.T, provider *mockOIDCProvider, autoProvision bool, adminGroup string) *Service {
	t.Helper()
	previous := config.ParsedConfig
	config.ParsedConfig = &internal.SylveConfig{Auth: internal.AuthConfig{OIDC: internal.OIDCConfig{
		Enabled: true, ProviderName: "Company SSO", IssuerURL: provider.server.URL,
		ClientID: "test-client", ClientSecret: "test-secret", RedirectURL: "https://sylve.example/",
		AutoProvision: autoProvision, AdminGroup: adminGroup, InsecureSkipVerify: true,
	}}}
	t.Cleanup(func() { config.ParsedConfig = previous })
	svc := newLocalTestService(t)
	if !svc.DB.Migrator().HasColumn(&models.User{}, "OIDCSubject") {
		t.Fatal("test users schema is missing OIDC subject")
	}
	if err := svc.DB.Create(&models.SystemSecrets{Name: "JWTSecret", Data: "test-jwt-secret"}).Error; err != nil {
		t.Fatalf("seed JWT secret: %v", err)
	}
	return svc
}

func beginMockOIDCLogin(t *testing.T, svc *Service, provider *mockOIDCProvider) (string, string) {
	t.Helper()
	authURL, err := svc.BeginOIDCLogin(t.Context(), "", true)
	if err != nil {
		t.Fatalf("begin OIDC login: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	state, nonce := parsed.Query().Get("state"), parsed.Query().Get("nonce")
	challenge := parsed.Query().Get("code_challenge")
	if state == "" || nonce == "" || challenge == "" || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("incomplete authorization URL: %s", authURL)
	}
	provider.mu.Lock()
	provider.nonce = nonce
	provider.challenge = challenge
	provider.mu.Unlock()
	return state, nonce
}

func TestFinishOIDCLoginBindsSubjectAndIssuesSession(t *testing.T) {
	provider := newMockOIDCProvider(t)
	service := newOIDCTestService(t, provider, false, "sylve-admins")
	user := seedUser(t, service, models.User{Username: "alice@corp.com", Source: "oidc", Admin: true, ExternallyManaged: true})
	provider.setClaims(map[string]any{
		"preferred_username": "alice@corp.com", "name": "Alice Example", "email": "alice@example.com",
		"email_verified": true, "groups": []string{"sylve-admins"},
	})
	state, _ := beginMockOIDCLogin(t, service, provider)

	loggedIn, token, err := service.FinishOIDCLogin(t.Context(), "auth-code", state)
	if err != nil {
		t.Fatalf("finish OIDC login: %v", err)
	}
	if loggedIn.ID != user.ID || loggedIn.OIDCSubject != "subject-1" || loggedIn.FullName != "Alice Example" || loggedIn.Email != "alice@example.com" {
		t.Fatalf("OIDC user after login = %+v", loggedIn)
	}
	claims, err := service.ValidateToken(token)
	if err != nil || claims.UserID != user.ID || claims.AuthType != AuthTypeOIDC {
		t.Fatalf("issued token claims=%+v err=%v", claims, err)
	}
	if _, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state); err == nil || err.Error() != "challenge_used" {
		t.Fatalf("replayed state error = %v, want challenge_used", err)
	}
}

func TestFinishOIDCLoginUsesUserInfoFallback(t *testing.T) {
	provider := newMockOIDCProvider(t)
	service := newOIDCTestService(t, provider, true, "sylve-admins")
	provider.setClaims(map[string]any{})
	provider.setUserInfo(map[string]any{
		"sub": "subject-1", "preferred_username": "new.user@corp.com", "name": "New User",
		"email": "new.user@example.com", "email_verified": true, "groups": []string{"sylve-admins"},
	})
	state, _ := beginMockOIDCLogin(t, service, provider)

	user, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state)
	if err != nil {
		t.Fatalf("finish OIDC login with UserInfo claims: %v", err)
	}
	if user.Username != "new.user@corp.com" || user.FullName != "New User" || user.Email != "new.user@example.com" || !user.Admin {
		t.Fatalf("UserInfo claims were not applied: %+v", user)
	}
}

func TestFinishOIDCLoginRejectsUnverifiedEmailFallback(t *testing.T) {
	provider := newMockOIDCProvider(t)
	service := newOIDCTestService(t, provider, true, "")
	provider.setClaims(map[string]any{"email": "victim@example.com", "email_verified": false})
	provider.setUserInfo(map[string]any{})
	state, _ := beginMockOIDCLogin(t, service, provider)

	if _, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state); err == nil || err.Error() != "invalid_credentials" {
		t.Fatalf("unverified email login error = %v, want invalid_credentials", err)
	}
}

func TestFinishOIDCLoginRejectsSourceAndSubjectCollisions(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
		sub    string
		want   string
	}{
		{name: "PAM username collision", source: "pam", want: "user_source_conflict"},
		{name: "local username collision", source: "local", want: "user_source_conflict"},
		{name: "OIDC subject mismatch", source: "oidc", sub: "different-subject", want: "invalid_credentials"},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := newMockOIDCProvider(t)
			service := newOIDCTestService(t, provider, true, "")
			seedUser(t, service, models.User{Username: "jdoe", Source: test.source, OIDCSubject: test.sub})
			provider.setClaims(map[string]any{"preferred_username": "jdoe"})
			state, _ := beginMockOIDCLogin(t, service, provider)
			if _, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state); err == nil || err.Error() != test.want {
				t.Fatalf("login error = %v, want %s", err, test.want)
			}
		})
	}
}

func TestFinishOIDCLoginAutoprovisionAndGroupAdmin(t *testing.T) {
	t.Run("no admin group defaults to admin", func(t *testing.T) {
		provider := newMockOIDCProvider(t)
		service := newOIDCTestService(t, provider, true, "")
		provider.setClaims(map[string]any{"preferred_username": "new.admin@corp.com"})
		state, _ := beginMockOIDCLogin(t, service, provider)
		user, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state)
		if err != nil || !user.Admin || user.Source != "oidc" || !user.ExternallyManaged || user.OIDCSubject != "subject-1" {
			t.Fatalf("auto-provisioned user=%+v err=%v", user, err)
		}
	})

	t.Run("configured group controls admin", func(t *testing.T) {
		provider := newMockOIDCProvider(t)
		service := newOIDCTestService(t, provider, true, "sylve-admins")
		provider.setClaims(map[string]any{"preferred_username": "new.user@corp.com", "groups": []string{"users"}})
		state, _ := beginMockOIDCLogin(t, service, provider)
		if _, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state); err == nil || err.Error() != "only_admin_allowed" {
			t.Fatalf("non-admin login error = %v, want only_admin_allowed", err)
		}
		user, err := service.GetUserByUsername("new.user@corp.com")
		if err != nil || user.Admin {
			t.Fatalf("persisted non-admin user=%+v err=%v", user, err)
		}
	})

	t.Run("preprovision disabled", func(t *testing.T) {
		provider := newMockOIDCProvider(t)
		service := newOIDCTestService(t, provider, false, "")
		provider.setClaims(map[string]any{"preferred_username": "missing@corp.com"})
		state, _ := beginMockOIDCLogin(t, service, provider)
		if _, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state); err == nil || err.Error() != "user_not_registered_in_sylve" {
			t.Fatalf("unregistered user error = %v, want user_not_registered_in_sylve", err)
		}
	})
}

func TestFinishOIDCLoginSyncsClaimsAndRevokesOldTokens(t *testing.T) {
	provider := newMockOIDCProvider(t)
	service := newOIDCTestService(t, provider, false, "sylve-admins")
	user := seedUser(t, service, models.User{
		Username: "oldname@corp.com", Source: "oidc", Admin: true, ExternallyManaged: true, OIDCSubject: "subject-1",
	})
	seedUserToken(t, service, user.ID, "old-oidc-session")
	provider.setClaims(map[string]any{
		"preferred_username": "newname@corp.com", "name": "Renamed User", "email": "newname@example.com",
		"email_verified": true, "groups": []string{"sylve-admins"},
	})
	state, _ := beginMockOIDCLogin(t, service, provider)

	updated, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state)
	if err != nil {
		t.Fatalf("finish OIDC login: %v", err)
	}
	if updated.Username != "newname@corp.com" || updated.FullName != "Renamed User" || updated.Email != "newname@example.com" || !updated.Admin {
		t.Fatalf("updated OIDC user = %+v", updated)
	}
	if count := userTokenCount(t, service, user.ID); count != 1 {
		t.Fatalf("tokens after login = %d, want only the newly issued session", count)
	}
}

func TestFinishOIDCLoginRejectsLockedUser(t *testing.T) {
	provider := newMockOIDCProvider(t)
	service := newOIDCTestService(t, provider, false, "")
	seedUser(t, service, models.User{
		Username: "locked@corp.com", Source: "oidc", Admin: true, Locked: true, OIDCSubject: "subject-1",
	})
	provider.setClaims(map[string]any{"preferred_username": "locked@corp.com"})
	state, _ := beginMockOIDCLogin(t, service, provider)
	if _, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state); err == nil || err.Error() != "account_locked" {
		t.Fatalf("locked OIDC account error = %v, want account_locked", err)
	}
}

func TestFinishOIDCLoginRevokesSessionsWhenAdminGroupIsRemoved(t *testing.T) {
	provider := newMockOIDCProvider(t)
	service := newOIDCTestService(t, provider, false, "sylve-admins")
	user := seedUser(t, service, models.User{
		Username: "admin@corp.com", Source: "oidc", Admin: true, ExternallyManaged: true, OIDCSubject: "subject-1",
	})
	seedUserToken(t, service, user.ID, "old-admin-session")
	provider.setClaims(map[string]any{
		"preferred_username": "admin@corp.com", "groups": []string{"users"},
	})
	state, _ := beginMockOIDCLogin(t, service, provider)
	if _, _, err := service.FinishOIDCLogin(t.Context(), "auth-code", state); err == nil || err.Error() != "only_admin_allowed" {
		t.Fatalf("removed admin group login error = %v, want only_admin_allowed", err)
	}
	updated, err := service.GetUserByID(user.ID)
	if err != nil || updated.Admin {
		t.Fatalf("admin group removal did not demote user: user=%+v err=%v", updated, err)
	}
	if count := userTokenCount(t, service, user.ID); count != 0 {
		t.Fatalf("sessions after admin group removal = %d, want 0", count)
	}
}

func TestOIDCTokensAreInvalidWhenOIDCIsDisabled(t *testing.T) {
	provider := newMockOIDCProvider(t)
	service := newOIDCTestService(t, provider, true, "")
	provider.setClaims(map[string]any{"preferred_username": "admin@corp.com"})
	state, _ := beginMockOIDCLogin(t, service, provider)
	user, token, err := service.FinishOIDCLogin(t.Context(), "auth-code", state)
	if err != nil {
		t.Fatalf("finish OIDC login: %v", err)
	}
	if err := service.DB.AutoMigrate(&clusterModels.Cluster{}); err != nil {
		t.Fatal(err)
	}
	if err := service.DB.Create(&clusterModels.Cluster{Enabled: true, Key: "cluster-secret"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := service.SetClusterIssuerNodeID("node-1"); err != nil {
		t.Fatal(err)
	}
	proxyToken, err := service.CreateUserProxyJWT(user.ID, user.Username, AuthTypeOIDC)
	if err != nil {
		t.Fatalf("create OIDC cluster proxy token: %v", err)
	}
	if _, err := service.VerifyClusterJWT(proxyToken); err != nil {
		t.Fatalf("verify OIDC cluster proxy token while enabled: %v", err)
	}

	config.ParsedConfig.Auth.OIDC.Enabled = false
	if service.VerifyTokenInDb(token) {
		t.Fatal("OIDC token remained valid after OIDC was disabled")
	}
	if _, err := service.VerifyClusterJWT(proxyToken); err == nil || err.Error() != "oidc_auth_disabled" {
		t.Fatalf("OIDC cluster proxy token error = %v, want oidc_auth_disabled", err)
	}
	if _, err := service.CreateUserProxyJWT(user.ID, user.Username, AuthTypeOIDC); err == nil || err.Error() != "proxy_user_not_authorized" {
		t.Fatalf("OIDC proxy token error = %v, want proxy_user_not_authorized", err)
	}
}
