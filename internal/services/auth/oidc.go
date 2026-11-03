// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2026 The FreeBSD Foundation.

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/alchemillahq/sylve/internal"
	"github.com/alchemillahq/sylve/internal/config"
	"github.com/alchemillahq/sylve/internal/db/models"
	"github.com/alchemillahq/sylve/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

const (
	oidcChallengeType = "oidc"
	oidcChallengeTTL  = 5 * time.Minute
	oidcRequestLimit  = 1 << 20
)

var oidcDiscoveryCache = struct {
	sync.RWMutex
	providers map[string]oidcProviderMetadata
}{providers: make(map[string]oidcProviderMetadata)}

type oidcLoginSession struct {
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier"`
	RedirectURI  string `json:"redirectURI"`
	Remember     bool   `json:"remember"`
}

type oidcProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

type oidcJWKSet struct {
	Keys []oidcJWK `json:"keys"`
}

type oidcJWK struct {
	Kty    string   `json:"kty"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`
	Alg    string   `json:"alg"`
	Kid    string   `json:"kid"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
}

type oidcIdentity struct {
	Subject  string
	Username string
	FullName string
	Email    string
	Groups   []string
}

func oidcHTTPClient(cfg internal.OIDCConfig) (*http.Client, error) {
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	var transport *http.Transport
	if ok {
		transport = baseTransport.Clone()
	} else {
		transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	if cfg.InsecureSkipVerify {
		// This is an explicit operator escape hatch for private/self-signed IdPs.
		tlsConfig.InsecureSkipVerify = true
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("oidc_ca_file_unreadable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("oidc_ca_file_invalid")
		}
		tlsConfig.RootCAs = roots
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func oidcDiscoveryKey(cfg internal.OIDCConfig) string {
	return cfg.IssuerURL + "\x00" + cfg.CAFile + "\x00" + fmt.Sprint(cfg.InsecureSkipVerify)
}

func validOIDCURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid_oidc_endpoint")
	}
	return u, nil
}

func oidcDiscoveryURL(issuer string) (string, error) {
	u, err := validOIDCURL(issuer)
	if err != nil || u.RawQuery != "" {
		return "", fmt.Errorf("invalid_oidc_issuer")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/.well-known/openid-configuration"
	u.RawPath = ""
	return u.String(), nil
}

func readOIDCJSON(resp *http.Response, destination any) error {
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("oidc_http_status_%d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, oidcRequestLimit+1))
	if err != nil {
		return fmt.Errorf("oidc_response_read_failed")
	}
	if len(body) > oidcRequestLimit {
		return fmt.Errorf("oidc_response_too_large")
	}
	if err := json.Unmarshal(body, destination); err != nil {
		return fmt.Errorf("oidc_response_invalid")
	}
	return nil
}

func oidcProvider(ctx context.Context, cfg internal.OIDCConfig, client *http.Client) (oidcProviderMetadata, error) {
	key := oidcDiscoveryKey(cfg)
	oidcDiscoveryCache.RLock()
	metadata, found := oidcDiscoveryCache.providers[key]
	oidcDiscoveryCache.RUnlock()
	if found {
		return metadata, nil
	}

	discoveryURL, err := oidcDiscoveryURL(cfg.IssuerURL)
	if err != nil {
		return oidcProviderMetadata{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return oidcProviderMetadata{}, fmt.Errorf("oidc_discovery_request_failed")
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return oidcProviderMetadata{}, fmt.Errorf("oidc_provider_unavailable")
	}
	if err := readOIDCJSON(response, &metadata); err != nil {
		return oidcProviderMetadata{}, fmt.Errorf("oidc_provider_unavailable")
	}
	if metadata.Issuer != cfg.IssuerURL {
		return oidcProviderMetadata{}, fmt.Errorf("oidc_issuer_mismatch")
	}
	for _, endpoint := range []string{metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.JWKSURI} {
		if _, err := validOIDCURL(endpoint); err != nil {
			return oidcProviderMetadata{}, fmt.Errorf("invalid_oidc_endpoint")
		}
	}
	if metadata.UserInfoEndpoint != "" {
		if _, err := validOIDCURL(metadata.UserInfoEndpoint); err != nil {
			return oidcProviderMetadata{}, fmt.Errorf("invalid_oidc_endpoint")
		}
	}

	oidcDiscoveryCache.Lock()
	oidcDiscoveryCache.providers[key] = metadata
	oidcDiscoveryCache.Unlock()
	return metadata, nil
}

func randomOIDCString(byteCount int) (string, error) {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("oidc_random_generation_failed")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (s *Service) BeginOIDCLogin(ctx context.Context, redirectURI string, remember bool) (string, error) {
	if !config.IsOIDCEnabled() {
		return "", fmt.Errorf("oidc_auth_disabled")
	}
	cfg := config.GetOIDCConfig()
	if cfg.RedirectURL != "" {
		redirectURI = cfg.RedirectURL
	}
	if _, err := validOIDCURL(redirectURI); err != nil {
		return "", fmt.Errorf("invalid_oidc_redirect_uri")
	}
	client, err := oidcHTTPClient(cfg)
	if err != nil {
		return "", err
	}
	defer client.CloseIdleConnections()
	provider, err := oidcProvider(ctx, cfg, client)
	if err != nil {
		return "", err
	}
	state, err := randomOIDCString(32)
	if err != nil {
		return "", err
	}
	nonce, err := randomOIDCString(32)
	if err != nil {
		return "", err
	}
	verifier, err := randomOIDCString(32)
	if err != nil {
		return "", err
	}
	challengeHash := sha256.Sum256([]byte(verifier))
	sessionData, err := json.Marshal(oidcLoginSession{
		Nonce: nonce, CodeVerifier: verifier, RedirectURI: redirectURI, Remember: remember,
	})
	if err != nil {
		return "", fmt.Errorf("oidc_challenge_encode_failed")
	}
	challenge := models.WebAuthnChallenge{
		RequestID: state, Type: oidcChallengeType, SessionData: sessionData,
		ExpiresAt: time.Now().Add(oidcChallengeTTL),
	}
	if err := s.DB.WithContext(ctx).Create(&challenge).Error; err != nil {
		return "", fmt.Errorf("oidc_challenge_store_failed")
	}

	endpoint, _ := url.Parse(provider.AuthorizationEndpoint)
	query := endpoint.Query()
	query.Set("client_id", cfg.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(cfg.Scopes, " "))
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challengeHash[:]))
	query.Set("code_challenge_method", "S256")
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func (s *Service) consumeOIDCChallenge(ctx context.Context, state string) (oidcLoginSession, error) {
	if state == "" || len(state) > 128 {
		return oidcLoginSession{}, fmt.Errorf("invalid_oidc_request")
	}
	var session oidcLoginSession
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var challenge models.WebAuthnChallenge
		if err := tx.Where("request_id = ? AND type = ?", state, oidcChallengeType).First(&challenge).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("challenge_not_found")
			}
			return fmt.Errorf("oidc_challenge_lookup_failed")
		}
		if challenge.Used {
			return fmt.Errorf("challenge_used")
		}
		if !time.Now().Before(challenge.ExpiresAt) {
			return fmt.Errorf("challenge_expired")
		}
		result := tx.Model(&models.WebAuthnChallenge{}).
			Where("id = ? AND used = ? AND expires_at > ?", challenge.ID, false, time.Now()).
			Update("used", true)
		if result.Error != nil {
			return fmt.Errorf("oidc_challenge_update_failed")
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("challenge_used")
		}
		if err := json.Unmarshal(challenge.SessionData, &session); err != nil {
			return fmt.Errorf("invalid_oidc_request")
		}
		if session.Nonce == "" || session.CodeVerifier == "" || session.RedirectURI == "" {
			return fmt.Errorf("invalid_oidc_request")
		}
		return nil
	})
	return session, err
}

func exchangeOIDCCode(ctx context.Context, client *http.Client, endpoint, clientID, clientSecret, code string, session oidcLoginSession) (oidcTokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {session.RedirectURI},
		"code_verifier": {session.CodeVerifier},
	}
	if clientSecret == "" {
		form.Set("client_id", clientID)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return oidcTokenResponse{}, fmt.Errorf("invalid_oidc_request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if clientSecret != "" {
		credentials := url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	response, err := client.Do(request)
	if err != nil {
		return oidcTokenResponse{}, fmt.Errorf("oidc_provider_unavailable")
	}
	var tokenResponse oidcTokenResponse
	if err := readOIDCJSON(response, &tokenResponse); err != nil {
		if response.StatusCode >= http.StatusBadRequest && response.StatusCode < http.StatusInternalServerError {
			return oidcTokenResponse{}, fmt.Errorf("invalid_credentials")
		}
		return oidcTokenResponse{}, fmt.Errorf("oidc_provider_unavailable")
	}
	if tokenResponse.IDToken == "" {
		return oidcTokenResponse{}, fmt.Errorf("invalid_credentials")
	}
	return tokenResponse, nil
}

func fetchOIDCJWKS(ctx context.Context, client *http.Client, endpoint string) (oidcJWKSet, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return oidcJWKSet{}, fmt.Errorf("oidc_jwks_request_failed")
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return oidcJWKSet{}, fmt.Errorf("oidc_provider_unavailable")
	}
	var keys oidcJWKSet
	if err := readOIDCJSON(response, &keys); err != nil || len(keys.Keys) == 0 {
		return oidcJWKSet{}, fmt.Errorf("oidc_provider_unavailable")
	}
	return keys, nil
}

func oidcSigningMethod(alg string) jwt.SigningMethod {
	switch alg {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "PS256":
		return jwt.SigningMethodPS256
	case "PS384":
		return jwt.SigningMethodPS384
	case "PS512":
		return jwt.SigningMethodPS512
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	case "EdDSA":
		return jwt.SigningMethodEdDSA
	default:
		return nil
	}
}

func oidcJWKPublicKey(key oidcJWK) (any, error) {
	switch key.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, fmt.Errorf("invalid_rsa_exponent")
		}
		var exponent uint64
		for _, b := range e {
			exponent = exponent<<8 | uint64(b)
		}
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 || exponent < 3 || exponent%2 == 0 || exponent > uint64(^uint(0)>>1) {
			return nil, fmt.Errorf("invalid_rsa_key")
		}
		return &rsa.PublicKey{N: modulus, E: int(exponent)}, nil
	case "EC":
		var curve elliptic.Curve
		switch key.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported_ec_curve")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return nil, err
		}
		x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("invalid_ec_key")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		if key.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported_okp_curve")
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid_ed25519_key")
		}
		return ed25519.PublicKey(publicKey), nil
	default:
		return nil, fmt.Errorf("unsupported_jwk_type")
	}
}

func oidcKeyFunc(keys oidcJWKSet) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok || oidcSigningMethod(alg) == nil {
			return nil, fmt.Errorf("unsupported_id_token_algorithm")
		}
		kid, _ := token.Header["kid"].(string)
		var matched *oidcJWK
		for i := range keys.Keys {
			key := &keys.Keys[i]
			if key.Use != "" && key.Use != "sig" {
				continue
			}
			if len(key.KeyOps) > 0 && !slices.Contains(key.KeyOps, "verify") {
				continue
			}
			if (strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")) && key.Kty != "RSA" {
				continue
			}
			if strings.HasPrefix(alg, "ES") && key.Kty != "EC" {
				continue
			}
			if alg == "EdDSA" && key.Kty != "OKP" {
				continue
			}
			if key.Alg != "" && key.Alg != alg {
				continue
			}
			if kid != "" && key.Kid != kid {
				continue
			}
			if matched != nil {
				return nil, fmt.Errorf("ambiguous_jwk")
			}
			matched = key
		}
		if matched == nil {
			return nil, fmt.Errorf("id_token_key_not_found")
		}
		return oidcJWKPublicKey(*matched)
	}
}

func verifyOIDCIDToken(ctx context.Context, client *http.Client, provider oidcProviderMetadata, clientID, rawToken, expectedNonce string) (jwt.MapClaims, error) {
	if rawToken == "" || len(rawToken) > oidcRequestLimit {
		return nil, fmt.Errorf("invalid_credentials")
	}
	keys, err := fetchOIDCJWKS(ctx, client, provider.JWKSURI)
	if err != nil {
		return nil, err
	}
	methods := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
	parsed, err := jwt.ParseWithClaims(rawToken, jwt.MapClaims{}, oidcKeyFunc(keys),
		jwt.WithValidMethods(methods),
		jwt.WithIssuer(provider.Issuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(time.Minute),
	)
	if err != nil || parsed == nil || !parsed.Valid {
		return nil, fmt.Errorf("invalid_credentials")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid_credentials")
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return nil, fmt.Errorf("invalid_credentials")
	}
	subject, _ := oidcStringClaim(claims, "sub")
	nonce, _ := oidcStringClaim(claims, "nonce")
	audience, err := claims.GetAudience()
	if subject == "" || err != nil || len(audience) == 0 || subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
		return nil, fmt.Errorf("invalid_credentials")
	}
	azp, azpPresent := oidcStringClaim(claims, "azp")
	if (azpPresent && azp != clientID) || (len(audience) > 1 && !azpPresent) {
		return nil, fmt.Errorf("invalid_credentials")
	}
	return claims, nil
}

func oidcStringClaim(claims map[string]any, name string) (string, bool) {
	value, exists := claims[name]
	if !exists {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		return "", true
	}
	return strings.TrimSpace(text), true
}

func oidcBoolClaim(claims map[string]any, name string) (bool, bool) {
	value, exists := claims[name]
	if !exists {
		return false, false
	}
	flag, ok := value.(bool)
	return flag, ok
}

func oidcStringSliceClaim(claims map[string]any, name string) ([]string, bool) {
	value, exists := claims[name]
	if !exists {
		return nil, false
	}
	switch values := value.(type) {
	case []string:
		return slices.DeleteFunc(values, func(value string) bool { return strings.TrimSpace(value) == "" }), true
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
		return out, true
	default:
		return nil, true
	}
}

func oidcUserInfo(ctx context.Context, client *http.Client, endpoint, accessToken string) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc_userinfo_request_failed")
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("oidc_provider_unavailable")
	}
	var claims map[string]any
	if err := readOIDCJSON(response, &claims); err != nil {
		return nil, fmt.Errorf("oidc_provider_unavailable")
	}
	return claims, nil
}

func oidcIdentityFromClaims(idClaims, infoClaims map[string]any, cfg internal.OIDCConfig) (oidcIdentity, error) {
	identity := oidcIdentity{}
	identity.Subject, _ = oidcStringClaim(idClaims, "sub")
	if identity.Subject == "" || len(identity.Subject) > 255 || strings.ContainsAny(identity.Subject, "\x00\r\n") {
		return identity, fmt.Errorf("invalid_credentials")
	}
	claimString := func(name string) string {
		if value, _ := oidcStringClaim(idClaims, name); value != "" {
			return value
		}
		value, _ := oidcStringClaim(infoClaims, name)
		return value
	}
	identity.FullName = claimString("name")
	idEmail, _ := oidcStringClaim(idClaims, "email")
	infoEmail, _ := oidcStringClaim(infoClaims, "email")
	idVerified, idVerificationPresent := oidcBoolClaim(idClaims, "email_verified")
	infoVerified, infoVerificationPresent := oidcBoolClaim(infoClaims, "email_verified")
	emailUnverified := (idVerificationPresent && !idVerified) || (infoVerificationPresent && !infoVerified)
	if !emailUnverified {
		identity.Email = idEmail
		if identity.Email == "" {
			identity.Email = infoEmail
		}
	}
	if identity.Email != "" && !utils.IsValidEmail(identity.Email) {
		identity.Email = ""
	}
	if cfg.UsernameClaim == "email" {
		identity.Username = identity.Email
	} else {
		identity.Username = claimString(cfg.UsernameClaim)
	}
	if identity.Username == "" {
		if emailUnverified && (idEmail != "" || infoEmail != "") {
			return identity, fmt.Errorf("invalid_credentials")
		}
		identity.Username = identity.Email
	}
	var groupsFound bool
	identity.Groups, groupsFound = oidcStringSliceClaim(idClaims, cfg.GroupsClaim)
	if !groupsFound {
		identity.Groups, _ = oidcStringSliceClaim(infoClaims, cfg.GroupsClaim)
	}
	return identity, nil
}

func oidcUserInfoIfNeeded(ctx context.Context, client *http.Client, provider oidcProviderMetadata, tokenResponse oidcTokenResponse, claims jwt.MapClaims, cfg internal.OIDCConfig) (map[string]any, error) {
	if provider.UserInfoEndpoint == "" || tokenResponse.AccessToken == "" {
		return nil, nil
	}
	missing := false
	if value, _ := oidcStringClaim(claims, cfg.UsernameClaim); value == "" {
		missing = true
	}
	if value, _ := oidcStringClaim(claims, "email"); value == "" {
		missing = true
	}
	if verified, exists := oidcBoolClaim(claims, "email_verified"); exists && !verified {
		missing = true
	}
	if value, _ := oidcStringClaim(claims, "name"); value == "" {
		missing = true
	}
	if cfg.AdminGroup != "" {
		if _, exists := claims[cfg.GroupsClaim]; !exists {
			missing = true
		}
	}
	if !missing {
		return nil, nil
	}
	infoClaims, err := oidcUserInfo(ctx, client, provider.UserInfoEndpoint, tokenResponse.AccessToken)
	if err != nil {
		return nil, err
	}
	idTokenSubject, _ := oidcStringClaim(claims, "sub")
	infoSubject, _ := oidcStringClaim(infoClaims, "sub")
	if idTokenSubject == "" || infoSubject != idTokenSubject {
		return nil, fmt.Errorf("invalid_credentials")
	}
	return infoClaims, nil
}

func (s *Service) resolveOIDCUser(ctx context.Context, identity oidcIdentity, cfg internal.OIDCConfig) (models.User, error) {
	var user models.User
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Where("source = ? AND oidc_subject = ?", AuthTypeOIDC, identity.Subject).First(&user).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("oidc_user_lookup_failed")
		}
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if identity.Username == "" || !utils.IsValidOIDCUsername(identity.Username) {
				return fmt.Errorf("invalid_credentials")
			}
			err = tx.Where("username = ?", identity.Username).First(&user).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("oidc_user_lookup_failed")
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				if !cfg.AutoProvision {
					return fmt.Errorf("user_not_registered_in_sylve")
				}
				admin := cfg.AdminGroup == "" || slices.Contains(identity.Groups, cfg.AdminGroup)
				user = models.User{
					Username: identity.Username, FullName: identity.FullName, Email: identity.Email,
					Admin: admin, Source: AuthTypeOIDC, ExternallyManaged: true,
					OIDCSubject: identity.Subject, Password: "", UID: 0,
					Shell: "/usr/sbin/nologin", HomeDirectory: "/nonexistent", HomeDirPerms: 0o755,
					DisablePassword: true,
				}
				if err := tx.Create(&user).Error; err != nil {
					if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
						return fmt.Errorf("user_source_conflict")
					}
					return fmt.Errorf("oidc_user_create_failed")
				}
				return nil
			}
			if user.Source != AuthTypeOIDC {
				return fmt.Errorf("user_source_conflict")
			}
			if user.OIDCSubject != "" && user.OIDCSubject != identity.Subject {
				return fmt.Errorf("invalid_credentials")
			}
			if user.OIDCSubject == "" {
				result := tx.Model(&models.User{}).
					Where("id = ? AND (oidc_subject = '' OR oidc_subject IS NULL)", user.ID).
					Update("oidc_subject", identity.Subject)
				if result.Error != nil {
					return fmt.Errorf("oidc_subject_bind_failed")
				}
				if result.RowsAffected != 1 {
					if err := tx.First(&user, user.ID).Error; err != nil || user.OIDCSubject != identity.Subject {
						return fmt.Errorf("invalid_credentials")
					}
				} else {
					user.OIDCSubject = identity.Subject
				}
			}
		}

		oldUsername, oldAdmin := user.Username, user.Admin
		updates := make(map[string]any)
		if identity.FullName != "" && identity.FullName != user.FullName {
			updates["full_name"] = identity.FullName
			user.FullName = identity.FullName
		}
		if identity.Email != "" && identity.Email != user.Email {
			updates["email"] = identity.Email
			user.Email = identity.Email
		}
		if identity.Username != "" && identity.Username != user.Username && utils.IsValidOIDCUsername(identity.Username) {
			var conflict models.User
			err := tx.Where("username = ? AND id != ?", identity.Username, user.ID).First(&conflict).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				updates["username"] = identity.Username
				user.Username = identity.Username
			} else if err != nil {
				return fmt.Errorf("oidc_username_lookup_failed")
			}
		}
		if cfg.AdminGroup != "" {
			user.Admin = slices.Contains(identity.Groups, cfg.AdminGroup)
			updates["admin"] = user.Admin
		}
		if len(updates) > 0 {
			if err := tx.Model(&models.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
				return fmt.Errorf("oidc_user_update_failed")
			}
		}
		if oldUsername != user.Username || oldAdmin != user.Admin {
			if err := s.revokeUserTokens(tx, user.ID); err != nil {
				return fmt.Errorf("oidc_session_revoke_failed")
			}
		}
		return nil
	})
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (s *Service) FinishOIDCLogin(ctx context.Context, code, state string) (models.User, string, error) {
	if !config.IsOIDCEnabled() {
		return models.User{}, "", fmt.Errorf("oidc_auth_disabled")
	}
	if strings.TrimSpace(code) == "" || len(code) > 8192 {
		return models.User{}, "", fmt.Errorf("invalid_oidc_request")
	}
	session, err := s.consumeOIDCChallenge(ctx, state)
	if err != nil {
		return models.User{}, "", err
	}
	cfg := config.GetOIDCConfig()
	client, err := oidcHTTPClient(cfg)
	if err != nil {
		return models.User{}, "", err
	}
	defer client.CloseIdleConnections()
	provider, err := oidcProvider(ctx, cfg, client)
	if err != nil {
		return models.User{}, "", err
	}
	tokenResponse, err := exchangeOIDCCode(ctx, client, provider.TokenEndpoint, cfg.ClientID, cfg.ClientSecret, code, session)
	if err != nil {
		return models.User{}, "", err
	}
	idClaims, err := verifyOIDCIDToken(ctx, client, provider, cfg.ClientID, tokenResponse.IDToken, session.Nonce)
	if err != nil {
		return models.User{}, "", err
	}
	infoClaims, err := oidcUserInfoIfNeeded(ctx, client, provider, tokenResponse, idClaims, cfg)
	if err != nil {
		return models.User{}, "", err
	}
	identity, err := oidcIdentityFromClaims(idClaims, infoClaims, cfg)
	if err != nil {
		return models.User{}, "", err
	}
	user, err := s.resolveOIDCUser(ctx, identity, cfg)
	if err != nil {
		return models.User{}, "", err
	}
	if user.Locked {
		return models.User{}, "", fmt.Errorf("account_locked")
	}
	if !user.Admin {
		return models.User{}, "", fmt.Errorf("only_admin_allowed")
	}
	token, err := s.issueJWT(user, AuthTypeOIDC, session.Remember)
	if err != nil {
		return models.User{}, "", err
	}
	return user, token, nil
}
