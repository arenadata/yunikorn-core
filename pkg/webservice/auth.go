/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

// Auth overview
//
// This file implements the authentication and authorization middleware used by
// YuniKorn web components (web UI and k8shim). Supported modes are configured
// via environment variables (see README) and include:
//  - mtls: mutual TLS — client certificate required and verified.
//  - shared_secret: HMAC-signed token provided in the Authorization header
//    ("Authorization: Token <token>"); the shared secret only signs and
//    verifies the token. The token format is:
//      <base64(payload)>.<hex(hmac_sha256(payload))>
//    where payload is JSON: {"user": string, "exp": unix_ts, "groups": [string]}
//  - ldap: BasicAuth credential check against LDAP. On success a signed cookie
//    `YK_AUTH` is issued containing the same token structure as above and
//    signed with the configured cookie/shared secret. The cookie is verified
//    on subsequent requests so that repeated Basic prompts are avoided.
//  - kerberos / kerberos_ldap: SPNEGO (Kerberos) authentication via keytab
//    (YUNIKORN_KEYTAB_PATH). kerberos_ldap additionally authorizes via LDAP
//    group lookups.
//
// Authorization
//  - Group membership is injected into the request identity (identity.AddToHTTPRequestContext)
//    as the `groups` attribute when available. LDAP-based authorization maps
//    configured role groups to roles: admin, viewer, service. Route-level
//    checks enforce access to cluster/scheduler/metrics endpoints.
//  - The `X-Groups` header can be enabled (`YUNIKORN_USE_X_GROUPS`) to allow
//    injecting upstream-provided groups into the request identity (useful for
//    reverse proxies that perform auth).
//
// Integration notes
//  - Authentication is split into two independent legs: user -> web (the
//    listener Mode above) and web -> k8shim. The web proxy always strips the
//    user's Authorization header; when YUNIKORN_K8SHIM_AUTH_SHARED_SECRET is
//    set it attaches a token signed from the authenticated request identity,
//    which the k8shim listener validates in its shared_secret mode.
//  - SPNEGO requires a valid keytab available via `YUNIKORN_KEYTAB_PATH`.
//  - Cookie signing and token verification use the configured shared secret
//    (YUNIKORN_AUTH_SHARED_SECRET or YUNIKORN_LDAP_COOKIE_SECRET).
//
// See yunikorn-core/README.md for configuration examples and environment
// variable names.

package webservice

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/x/identity"
	"github.com/go-ldap/ldap/v3"
)

type AuthMode string

const (
	// AuthModeNone explicitly disables authentication; only valid as the
	// metrics authentication override.
	AuthModeNone         AuthMode = "none"
	AuthModeMTLS         AuthMode = "mtls"
	AuthModeSharedSecret AuthMode = "shared_secret"
	AuthModeLDAP         AuthMode = "ldap"
	AuthModeKerberos     AuthMode = "kerberos"
	AuthModeKerberosLDAP AuthMode = "kerberos_ldap"
)

func parseAuthMode(raw string) AuthMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(AuthModeMTLS):
		return AuthModeMTLS
	case string(AuthModeSharedSecret):
		return AuthModeSharedSecret
	case string(AuthModeLDAP):
		return AuthModeLDAP
	case string(AuthModeKerberos):
		return AuthModeKerberos
	case string(AuthModeKerberosLDAP):
		return AuthModeKerberosLDAP
	default:
		return ""
	}
}

// Middleware wraps an http.Handler with additional behaviour.
type Middleware func(http.Handler) http.Handler

// Middlewares returns the authentication middleware set for the configured
// mode, in execution order. Role based authorization is not part of the set:
// the web server applies it per route, by route name (see authorizeRoute).
func (cfg *Config) Middlewares() []Middleware {
	if cfg == nil {
		return nil
	}

	var mw []Middleware
	switch cfg.Mode {
	case AuthModeMTLS:
		mw = append(mw, cfg.mtlsAuth)
	case AuthModeSharedSecret:
		mw = append(mw, cfg.tokenAuth)
		if cfg.LDAP != nil {
			mw = append(mw, cfg.ldapGroups)
		}
		mw = append(mw, cfg.requireAuth)
	case AuthModeLDAP:
		mw = append(mw, cfg.cookieAuth, cfg.ldapBasicAuth)
	case AuthModeKerberos:
		mw = append(mw, cfg.spnegoAuth, cfg.xGroupsHeader)
	case AuthModeKerberosLDAP:
		mw = append(mw, cfg.spnegoAuth, cfg.xGroupsHeader)
	default:
		// no explicit mode: a keytab-only configuration still enforces SPNEGO
		if cfg.KeytabPath != "" {
			mw = append(mw, cfg.spnegoAuth, cfg.xGroupsHeader)
		}
	}
	return mw
}

// Wrap applies the configured middleware set to next. The first middleware in
// the set becomes the outermost handler and therefore runs first.
func (cfg *Config) Wrap(next http.Handler) http.Handler {
	mw := cfg.Middlewares()
	for i := len(mw) - 1; i >= 0; i-- {
		next = mw[i](next)
	}
	return next
}

// tokenPayload is the JSON structure expected inside the signed token
type tokenPayload struct {
	User   string   `json:"user"`
	Exp    int64    `json:"exp"`
	Groups []string `json:"groups,omitempty"`
	// Name is the display name read during the bind; tokens without it stay valid
	Name string `json:"name,omitempty"`
	// Auth is the login time, kept across renewals; a token without it is not renewed
	Auth int64 `json:"auth,omitempty"`
}

// webIdentity is a minimal Identity implementation for attaching to requests
type webIdentity struct {
	user          string
	domain        string
	displayName   string
	human         bool
	authTime      time.Time
	authzAttribs  []string
	authenticated bool
	sessionID     string
	expires       time.Time
	attrs         map[string]any
}

func newWebIdentity(user string, groups []string, exp int64) *webIdentity {
	wi := &webIdentity{user: user, attrs: map[string]any{}}
	if groups != nil {
		wi.authzAttribs = append([]string{}, groups...)
		wi.attrs["groups"] = groups
	}
	if exp > 0 {
		wi.expires = time.Unix(exp, 0)
	}
	wi.authenticated = true
	wi.authTime = time.Now()
	return wi
}

func (w *webIdentity) UserName() string            { return w.user }
func (w *webIdentity) SetUserName(s string)        { w.user = s }
func (w *webIdentity) Domain() string              { return w.domain }
func (w *webIdentity) SetDomain(s string)          { w.domain = s }
func (w *webIdentity) DisplayName() string         { return w.displayName }
func (w *webIdentity) SetDisplayName(s string)     { w.displayName = s }
func (w *webIdentity) Human() bool                 { return w.human }
func (w *webIdentity) SetHuman(b bool)             { w.human = b }
func (w *webIdentity) AuthTime() time.Time         { return w.authTime }
func (w *webIdentity) SetAuthTime(t time.Time)     { w.authTime = t }
func (w *webIdentity) AuthzAttributes() []string   { return append([]string{}, w.authzAttribs...) }
func (w *webIdentity) AddAuthzAttribute(a string)  { w.authzAttribs = append(w.authzAttribs, a) }
func (w *webIdentity) RemoveAuthzAttribute(string) { /* no-op */ }
func (w *webIdentity) Authenticated() bool         { return w.authenticated }
func (w *webIdentity) SetAuthenticated(b bool)     { w.authenticated = b }
func (w *webIdentity) Authorized(a string) bool {
	return slices.Contains(w.authzAttribs, a)
}
func (w *webIdentity) SessionID() string { return w.sessionID }
func (w *webIdentity) Expired() bool {
	if w.expires.IsZero() {
		return false
	}
	return time.Now().After(w.expires)
}
func (w *webIdentity) Attributes() map[string]any     { return w.attrs }
func (w *webIdentity) SetAttribute(k string, v any)   { w.attrs[k] = v }
func (w *webIdentity) SetAttributes(m map[string]any) { w.attrs = m }
func (w *webIdentity) RemoveAttribute(k string)       { delete(w.attrs, k) }
func (w *webIdentity) Marshal() ([]byte, error)       { return json.Marshal(w.attrs) }
func (w *webIdentity) Unmarshal(b []byte) error       { return json.Unmarshal(b, &w.attrs) }

// tokenAuth validates the "Authorization: Token <token>" scheme when present:
// a valid token attaches the identity to the request context, an invalid one is
// rejected. Requests without a Token header pass through unauthenticated so
// that a following middleware (requireAuth or another authenticator) decides.
func (cfg *Config) tokenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Token") {
			next.ServeHTTP(w, r)
			return
		}
		tp, ok := verifyToken(cfg.SharedSecret, parts[1])
		if !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		r = identity.AddToHTTPRequestContext(newWebIdentity(tp.User, tp.Groups, tp.Exp), r)
		next.ServeHTTP(w, r)
	})
}

// requireAuth rejects requests that reached it without an authenticated
// identity.
func (cfg *Config) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity.FromHTTPRequestContext(r) == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ldapGroups enriches an authenticated identity that carries no groups yet
// with the membership looked up in LDAP.
func (cfg *Config) ldapGroups(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := identity.FromHTTPRequestContext(r); id != nil && cfg.LDAP != nil && !identityHasGroups(id) {
			if groups, err := cfg.LDAP.getGroupMembership(id.UserName()); err == nil {
				groupList := make([]string, 0, len(groups))
				for g := range groups {
					groupList = append(groupList, g)
				}
				for _, g := range groupList {
					id.AddAuthzAttribute(g)
				}
				id.SetAttribute("groups", groupList)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func identityHasGroups(id identity.Identity) bool {
	if attrs := id.Attributes(); attrs != nil {
		if g, ok := attrs["groups"].([]string); ok && len(g) > 0 {
			return true
		}
	}
	return false
}

// mtlsAuth requires a verified client certificate on the TLS connection.
func (cfg *Config) mtlsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.ValidateMTLS(r) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	})
}

// spnegoAuth enforces SPNEGO (Kerberos) authentication via the configured
// keytab; requests already authenticated by an earlier middleware pass
// through. A missing or broken keytab rejects all requests instead of
// silently disabling authentication.
func (cfg *Config) spnegoAuth(next http.Handler) http.Handler {
	var spnegoHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "SPNEGO authentication unavailable", http.StatusUnauthorized)
	})
	if cfg.KeytabPath != "" {
		if kt, err := keytab.Load(cfg.KeytabPath); err == nil {
			spnegoHandler = spnego.SPNEGOKRB5Authenticate(next, kt)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity.FromHTTPRequestContext(r) != nil {
			next.ServeHTTP(w, r)
			return
		}
		spnegoHandler.ServeHTTP(w, r)
	})
}

// xGroupsHeader injects groups provided by an upstream proxy via the X-Groups
// header into the authenticated identity (enabled with YUNIKORN_USE_X_GROUPS).
func (cfg *Config) xGroupsHeader(next http.Handler) http.Handler {
	if !cfg.UseXGroups {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("X-Groups")
		if header != "" {
			id := identity.FromHTTPRequestContext(r)
			if id != nil {
				parts := strings.Split(header, ",")
				groupList := make([]string, 0, len(parts))
				for _, p := range parts {
					if s := strings.TrimSpace(p); s != "" {
						groupList = append(groupList, normalizeGroupName(s))
					}
				}
				if len(groupList) > 0 {
					id.SetAttribute("groups", groupList)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// cookieAuth authenticates repeated visits via the signed YK_AUTH cookie;
// requests without a valid cookie pass through to the next authenticator.
func (cfg *Config) cookieAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("YK_AUTH"); err == nil {
			if tp, ok := verifyToken(cfg.SharedSecret, cookie.Value); ok {
				if renewed := cfg.renewAuthCookie(tp); renewed != nil {
					http.SetCookie(w, renewed)
				}
				id := newWebIdentity(tp.User, tp.Groups, tp.Exp)
				id.SetDisplayName(tp.Name)
				r = identity.AddToHTTPRequestContext(id, r)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ldapBasicAuth verifies BasicAuth credentials against LDAP, issues the signed
// YK_AUTH cookie and attaches the identity to the request context; requests
// already authenticated by an earlier middleware pass through.
func (cfg *Config) ldapBasicAuth(next http.Handler) http.Handler {
	return cfg.basicAuth(next, true)
}

// basicAuth is ldapBasicAuth with the rejection made optional: a public route
// passes require false and continues unauthenticated instead of rejecting.
func (cfg *Config) basicAuth(next http.Handler, require bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity.FromHTTPRequestContext(r) != nil {
			next.ServeHTTP(w, r)
			return
		}
		// answer the error, or let a public route continue without an identity
		fail := func(message string, code int) {
			if require {
				http.Error(w, message, code)
				return
			}
			next.ServeHTTP(w, r)
		}
		username, password, ok := r.BasicAuth()
		if !ok {
			if require && !cfg.NoBasicChallenge {
				w.Header().Set("WWW-Authenticate", `Basic realm="yunikorn"`)
			}
			fail("Authentication required", http.StatusUnauthorized)
			return
		}
		if cfg.LDAP == nil {
			fail("LDAP not configured", http.StatusInternalServerError)
			return
		}
		groups, displayName, err := cfg.ldapBind(username, password)
		if err != nil {
			fail("Authentication failed", http.StatusUnauthorized)
			return
		}
		if cfg.SharedSecret == "" {
			fail("Cookie signing not configured", http.StatusInternalServerError)
			return
		}
		cookie := cfg.newAuthCookie(username, groups, displayName)
		http.SetCookie(w, cookie)

		id := newWebIdentity(username, groups, cookie.Expires.Unix())
		id.SetDisplayName(displayName)
		r = identity.AddToHTTPRequestContext(id, r)
		next.ServeHTTP(w, r)
	})
}

// ldapBind verifies the password by binding as the user and returns the groups
// the user belongs to and the display name of the user entry.
func (cfg *Config) ldapBind(username, password string) ([]string, string, error) {
	// Connect to LDAP (with service account if configured)
	conn, err := cfg.LDAP.connect()
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = conn.Close() }()

	userDN, _, displayName, err := cfg.LDAP.searchUserWithConn(conn, username)
	if err != nil {
		return nil, "", err
	}
	// Verify password by binding as the user on the same connection
	if err = conn.Bind(userDN, password); err != nil {
		return nil, "", err
	}
	// Fetch groups
	groups, err := cfg.LDAP.lookupGroupsWithConn(conn, username, userDN)
	if err != nil {
		return nil, "", err
	}
	groupList := make([]string, 0, len(groups))
	for g := range groups {
		groupList = append(groupList, g)
	}
	return groupList, displayName, nil
}

// newAuthCookie builds the signed YK_AUTH cookie of a fresh login.
func (cfg *Config) newAuthCookie(username string, groups []string, displayName string) *http.Cookie {
	login := time.Now()
	return cfg.authCookie(tokenPayload{
		User: username, Groups: groups, Name: displayName, Auth: login.Unix(),
	}, login)
}

// authCookie signs tp with an expiry of CookieTTL from now, never later than
// SessionMaxLifetime after the login.
func (cfg *Config) authCookie(tp tokenPayload, login time.Time) *http.Cookie {
	expires := time.Now().Add(cfg.LDAP.CookieTTL)
	if limit := login.Add(cfg.LDAP.SessionMaxLifetime); expires.After(limit) {
		expires = limit
	}
	tp.Exp = expires.Unix()
	return &http.Cookie{
		Name:     "YK_AUTH",
		Value:    signPayload(cfg.SharedSecret, tp),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
	}
}

// renewAuthCookie re-issues a cookie that is past half its lifetime, so that an
// active user is not logged out in the middle of work. CookieTTL is therefore
// an idle timeout. It returns nil when there is nothing to renew: a cookie
// issued before this was added, or one already at the absolute limit.
func (cfg *Config) renewAuthCookie(tp tokenPayload) *http.Cookie {
	if cfg.LDAP == nil || tp.Auth == 0 {
		return nil
	}
	if time.Until(time.Unix(tp.Exp, 0)) > cfg.LDAP.CookieTTL/2 {
		return nil
	}
	cookie := cfg.authCookie(tp, time.Unix(tp.Auth, 0))
	if cookie.Expires.Unix() <= tp.Exp {
		return nil
	}
	return cookie
}

// expireAuthCookie clears YK_AUTH in the browser; the flags must match the ones
// it was set with.
func expireAuthCookie() *http.Cookie {
	return &http.Cookie{
		Name:     "YK_AUTH",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
}

// enforcedMode is the mode actually applied, which is what whoami reports: a
// keytab without an explicit mode enforces kerberos.
func (cfg *Config) enforcedMode() AuthMode {
	if cfg == nil || (cfg.Mode == "" && cfg.KeytabPath == "") {
		return AuthModeNone
	}
	if cfg.Mode == "" {
		return AuthModeKerberos
	}
	return cfg.Mode
}

// publicRoute reports routes served without a session. Only the ldap mode has
// them: the SPA must load and call /auth/* before anyone has logged in.
func (cfg *Config) publicRoute(name string) bool {
	if cfg == nil || cfg.Mode != AuthModeLDAP {
		return false
	}
	return name == RouteNameStaticUI || name == RouteNameAuth
}

// wrapRoute authenticates one route. A public route is never rejected, but the
// chain still runs, so a cookie sent with the request is read.
func (cfg *Config) wrapRoute(name string, next http.Handler) http.Handler {
	if !cfg.publicRoute(name) {
		return cfg.Wrap(next)
	}
	return cfg.cookieAuth(cfg.basicAuth(next, false))
}

// SignToken builds an HMAC-signed token (base64(payload).hex(signature)) used
// with the "Authorization: Token <token>" scheme and the YK_AUTH cookie.
func SignToken(secret, user string, groups []string, expires time.Time) string {
	return signPayload(secret, tokenPayload{User: user, Exp: expires.Unix(), Groups: groups})
}

// signPayload signs a full payload, for the fields SignToken does not take.
func signPayload(secret string, tp tokenPayload) string {
	payload, _ := json.Marshal(tp)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return base64.StdEncoding.EncodeToString(payload) + "." + hex.EncodeToString(mac.Sum(nil))
}

// verifyToken checks the signature and expiry of a signed token and returns
// its payload.
func verifyToken(secret, token string) (tokenPayload, bool) {
	var tp tokenPayload
	if secret == "" {
		return tp, false
	}
	segs := strings.Split(token, ".")
	if len(segs) != 2 {
		return tp, false
	}
	payload, err := base64.StdEncoding.DecodeString(segs[0])
	if err != nil {
		return tp, false
	}
	sig, err := hex.DecodeString(segs[1])
	if err != nil {
		return tp, false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return tp, false
	}
	if err := json.Unmarshal(payload, &tp); err != nil {
		return tp, false
	}
	if tp.Exp != 0 && time.Now().Unix() > tp.Exp {
		return tp, false
	}
	return tp, true
}

func (cfg *Config) ValidateMTLS(r *http.Request) bool {
	if cfg == nil || cfg.Mode != AuthModeMTLS {
		return false
	}
	return r.TLS != nil && len(r.TLS.PeerCertificates) > 0
}

func (c *LDAPConfig) TLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify}
	if len(c.CAFile) > 0 {
		caCert, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		cfg.ClientCAs = pool
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// authorizeRoute guards a named route. With authentication enabled, routes
// with an unknown category are not served at all (403); the modes that
// authorize via LDAP groups additionally get role based access control.
func (cfg *Config) authorizeRoute(name string, next http.Handler) http.Handler {
	if cfg == nil || len(cfg.Middlewares()) == 0 {
		// authentication disabled
		return next
	}
	if !knownRouteName(name) {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
	// the auth endpoints need no role, and a public route has no identity to
	// check a role on
	if name == RouteNameAuth || cfg.publicRoute(name) {
		return next
	}
	if cfg.LDAP == nil || (cfg.Mode != AuthModeLDAP && cfg.Mode != AuthModeKerberosLDAP) {
		return next
	}
	return cfg.LDAP.Authorize(name, next)
}

// Authorize enforces role based access control for the named route based on
// LDAP group membership: the admin role is allowed everything, viewer the
// Scheduler routes, service the Metrics routes. Groups listed in
// YUNIKORN_LDAP_ALLOWED_GROUPS are allowed any route without a role.
func (c *LDAPConfig) Authorize(routeName string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromHTTPRequestContext(r)
		if id == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user := parsePrincipalUser(id.UserName())
		var groups map[string]bool
		if attrs := id.Attributes(); attrs != nil {
			if g, ok := attrs["groups"]; ok {
				if sl, ok := g.([]string); ok {
					groups = make(map[string]bool)
					for _, gg := range sl {
						groups[normalizeGroupName(gg)] = true
					}
				}
				if sl2, ok := g.([]interface{}); ok {
					groups = make(map[string]bool)
					for _, gi := range sl2 {
						if s, ok := gi.(string); ok {
							groups[normalizeGroupName(s)] = true
						}
					}
				}
			}
		}

		var err error
		if groups == nil {
			groups, err = c.getGroupMembership(user)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		var role string
		for g := range groups {
			if c.AdminGroups != nil && c.AdminGroups[g] {
				role = "admin"
				break
			}
		}

		if role == "" {
			for g := range groups {
				if c.ViewerGroups != nil && c.ViewerGroups[g] {
					role = "viewer"
					break
				}
			}
		}
		if role == "" {
			for g := range groups {
				if c.ServiceGroups != nil && c.ServiceGroups[g] {
					role = "service"
					break
				}
			}
		}

		if role == "" && c.AllowedGroups != nil {
			for g := range groups {
				if c.AllowedGroups[g] {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		switch role {
		case "admin":
			next.ServeHTTP(w, r)
			return
		case "viewer":
			if routeName == RouteNameScheduler {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		case "service":
			if routeName == RouteNameMetrics {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		default:
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	})
}

func parsePrincipalUser(principal string) string {
	if idx := strings.IndexByte(principal, '@'); idx >= 0 {
		principal = principal[:idx]
	}
	return strings.TrimSpace(principal)
}

type groupCacheEntry struct {
	groups  map[string]bool
	expires time.Time
}

type groupCache struct {
	mu      sync.RWMutex
	entries map[string]groupCacheEntry
	ttl     time.Duration
}

func newGroupCache(ttl time.Duration) *groupCache {
	return &groupCache{entries: make(map[string]groupCacheEntry), ttl: ttl}
}

func (c *groupCache) get(key string) (map[string]bool, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return cloneGroupMap(entry.groups), true
}

func (c *groupCache) set(key string, groups map[string]bool) {
	c.mu.Lock()
	c.entries[key] = groupCacheEntry{groups: cloneGroupMap(groups), expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

func cloneGroupMap(groups map[string]bool) map[string]bool {
	clone := make(map[string]bool, len(groups))
	maps.Copy(clone, groups)
	return clone
}

func (c *LDAPConfig) isAuthorized(username string) (bool, error) {
	groups, err := c.getGroupMembership(username)
	if err != nil {
		return false, err
	}
	for group := range groups {
		if c.AllowedGroups[group] {
			return true, nil
		}
	}
	return false, nil
}

func (c *LDAPConfig) getGroupMembership(username string) (map[string]bool, error) {
	// use the global cache attached to the config
	if c.cache == nil {
		c.cache = newGroupCache(c.CacheTTL)
	}
	if groups, ok := c.cache.get(username); ok {
		return groups, nil
	}
	groups, err := c.lookupGroups(username)
	if err != nil {
		return nil, err
	}
	c.cache.set(username, groups)
	return groups, nil
}

func (c *LDAPConfig) lookupGroups(username string) (map[string]bool, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	return c.lookupGroupsWithConn(conn, username, "")
}

// lookupGroupsWithConn reuses an existing LDAP connection to retrieve groups for a user.
func (c *LDAPConfig) lookupGroupsWithConn(conn *ldap.Conn, username, userDN string) (map[string]bool, error) {
	userDNresp, memberOf, _, err := c.searchUserWithConn(conn, username)
	if err != nil {
		return nil, err
	}
	if len(userDN) == 0 {
		userDN = userDNresp
	}

	groups := make(map[string]bool)
	for _, rawGroup := range memberOf {
		for _, normalized := range normalizeLDAPGroupNames(rawGroup) {
			groups[normalized] = true
		}
	}
	if len(groups) == 0 {
		more, err := c.searchGroupEntriesWithConn(conn, username, userDN)
		if err != nil {
			return nil, err
		}
		for group := range more {
			groups[group] = true
		}
	}
	return groups, nil
}

// searchUserWithConn returns the user DN, the group attribute values and the
// display name (displayName, else cn).
func (c *LDAPConfig) searchUserWithConn(conn *ldap.Conn, username string) (string, []string, string, error) {
	filter := fmt.Sprintf("(|(uid=%[1]s)(sAMAccountName=%[1]s)(cn=%[1]s))", ldap.EscapeFilter(username))
	search := ldap.NewSearchRequest(
		cmp.Or(c.UserBaseDN, c.BaseDN),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		[]string{"dn", c.GroupAttribute, "displayName", "cn"},
		nil,
	)
	result, err := conn.Search(search)
	if err != nil {
		return "", nil, "", fmt.Errorf("ldap search error: %w", err)
	}
	if len(result.Entries) == 0 {
		return "", nil, "", fmt.Errorf("ldap user %s not found", username)
	}
	entry := result.Entries[0]
	displayName := cmp.Or(entry.GetAttributeValue("displayName"), entry.GetAttributeValue("cn"))
	return entry.DN, entry.GetAttributeValues(c.GroupAttribute), displayName, nil
}

func (c *LDAPConfig) searchGroupEntriesWithConn(conn *ldap.Conn, username, userDN string) (map[string]bool, error) {
	filter := fmt.Sprintf("(|(member=%s)(memberUid=%s))", ldap.EscapeFilter(userDN), ldap.EscapeFilter(username))
	search := ldap.NewSearchRequest(
		c.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"dn", "cn"},
		nil,
	)
	result, err := conn.Search(search)
	if err != nil {
		return nil, err
	}
	groups := make(map[string]bool)
	for _, entry := range result.Entries {
		for _, normalized := range normalizeLDAPGroupNames(entry.DN) {
			groups[normalized] = true
		}
		if cn := entry.GetAttributeValue("cn"); cn != "" {
			groups[normalizeGroupName(cn)] = true
		}
	}
	return groups, nil
}

// connect establishes an LDAP connection and binds with the service account.
// For ldaps:// URLs it applies the configured TLS settings before dialling.
func (c *LDAPConfig) connect() (*ldap.Conn, error) {
	if c.URL == "" {
		return nil, fmt.Errorf("ldap URL not configured")
	}
	isLDAPS := strings.HasPrefix(strings.ToLower(c.URL), "ldaps://")
	var tlsConfig *tls.Config
	if isLDAPS {
		var err error
		tlsConfig, err = c.TLSConfig()
		if err != nil {
			return nil, fmt.Errorf("ldaps TLS config: %w", err)
		}
	}
	var conn *ldap.Conn
	var err error
	if isLDAPS {
		conn, err = ldap.DialURL(c.URL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(c.URL)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap dial error: %w", err)
	}
	// Bind with service account (if credentials provided)
	if c.BindDN != "" && c.BindPassword != "" {
		if err = conn.Bind(c.BindDN, c.BindPassword); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ldap bind error: %w", err)
		}
	}
	return conn, nil
}

// searchUser (public) performs a one-off connection to find the user's DN and memberOf attribute.
func (c *LDAPConfig) searchUser(username string) (string, []string, error) {
	conn, err := c.connect()
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = conn.Close() }()
	dn, memberOf, _, err := c.searchUserWithConn(conn, username)
	return dn, memberOf, err
}

// searchGroupEntries (public) is a convenience wrapper for external callers.
func (c *LDAPConfig) searchGroupEntries(username, userDN string) (map[string]bool, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return c.searchGroupEntriesWithConn(conn, username, userDN)
}

func normalizeGroupName(group string) string {
	return strings.ToLower(strings.TrimSpace(group))
}

// normalizeLDAPGroupNames returns the names a raw group value may be matched
// against: for an entry DN the value of its leading RDN - the group's cn -
// otherwise the value itself, lowercased and trimmed.
func normalizeLDAPGroupNames(raw string) []string {
	values := []string{normalizeGroupName(raw)}
	dn, err := ldap.ParseDN(raw)
	// an empty value parses without error into a DN with no RDNs
	if err != nil || len(dn.RDNs) == 0 {
		return values
	}
	if cn := normalizeGroupName(dn.RDNs[0].Attributes[0].Value); cn != "" {
		return []string{cn}
	}
	return values
}
