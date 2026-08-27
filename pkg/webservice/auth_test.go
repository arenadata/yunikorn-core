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

package webservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/x/identity"
	"github.com/shulutkov/krb5test"
	"gotest.tools/v3/assert"
)

func TestMTLSAuthMiddleware(t *testing.T) {
	cfg := &Config{Mode: AuthModeMTLS}
	handler := cfg.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusUnauthorized)

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusNoContent)
}

func TestSPNEGOAuthMiddleware(t *testing.T) {
	kdc, err := krb5test.NewKDC(map[string][]string{
		"testuser1":      {},
		"HTTP/localhost": {},
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("create kerberos kdc: %v", err)
	}
	kdc.Start()
	t.Cleanup(kdc.Close)

	serviceKT, err := kdc.NewKeytab("HTTP/localhost")
	if err != nil {
		t.Fatalf("create service keytab: %v", err)
	}
	keytabFile := filepath.Join(t.TempDir(), "service.keytab")
	data, err := serviceKT.Marshal()
	if err != nil {
		t.Fatalf("marshal service keytab: %v", err)
	}
	if err := os.WriteFile(keytabFile, data, 0o600); err != nil {
		t.Fatalf("write service keytab: %v", err)
	}

	var authenticatedUser string
	cfg := &Config{KeytabPath: keytabFile}
	handler := cfg.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := identity.FromHTTPRequestContext(r); id != nil {
			authenticatedUser = id.UserName()
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	noAuthReq, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("create unauthenticated request: %v", err)
	}
	resp, err := http.DefaultClient.Do(noAuthReq)
	if err != nil {
		t.Fatalf("perform unauthenticated request: %v", err)
	}
	assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)

	userKT, err := kdc.NewKeytab("testuser1")
	if err != nil {
		t.Fatalf("create client keytab: %v", err)
	}
	cl := client.NewWithKeytab("testuser1", kdc.Realm, userKT, kdc.KRB5Conf)
	if err := cl.Login(); err != nil {
		t.Fatalf("login client: %v", err)
	}

	authReq, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("create authenticated request: %v", err)
	}
	if err := spnego.SetSPNEGOHeader(cl, authReq, "HTTP/localhost"); err != nil {
		t.Fatalf("set spnego header: %v", err)
	}
	resp, err = http.DefaultClient.Do(authReq)
	if err != nil {
		t.Fatalf("perform authenticated request: %v", err)
	}
	assert.Equal(t, resp.StatusCode, http.StatusNoContent)
	assert.Assert(t, authenticatedUser != "")
	assert.Assert(t, strings.Contains(authenticatedUser, "testuser1"))
}

// TestSPNEGOKeytabError ensures that a broken keytab path results in 401, not passthrough.
func TestSPNEGOKeytabError(t *testing.T) {
	cfg := &Config{
		Mode:       AuthModeKerberos,
		KeytabPath: "/nonexistent/keytab",
	}
	handler := cfg.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusUnauthorized)
	assert.Assert(t, strings.Contains(rr.Body.String(), "SPNEGO authentication unavailable"))
}

// ----------------- Cookie authentication tests -----------------
func signToken(secret string, tp tokenPayload) string {
	payload, _ := json.Marshal(tp)
	enc := base64.StdEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := hex.EncodeToString(mac.Sum(nil))
	return enc + "." + sig
}

func TestCookieAuthValid(t *testing.T) {
	secret := "test-secret"
	cfg := &Config{
		Mode:         AuthModeLDAP,
		SharedSecret: secret,
		LDAP:         &LDAPConfig{},
	}
	token := signToken(secret, tokenPayload{
		User:   "testuser",
		Exp:    time.Now().Add(time.Hour).Unix(),
		Groups: []string{"group-a"},
	})

	var capturedUser string
	handler := cfg.cookieAuth(cfg.ldapBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromHTTPRequestContext(r)
		if id != nil {
			capturedUser = id.UserName()
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "YK_AUTH", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusNoContent)
	assert.Equal(t, capturedUser, "testuser")
}

// TestRouteAuthorization ensures role based authorization is applied per
// route, driven by the route category name, and that routes with an unknown
// category are not served when authentication is enabled.
func TestRouteAuthorization(t *testing.T) {
	secret := "test-secret"
	cfg := &Config{
		Mode:         AuthModeLDAP,
		SharedSecret: secret,
		LDAP: &LDAPConfig{
			AdminGroups:   GroupSet{"admins": true},
			ViewerGroups:  GroupSet{"viewers": true},
			ServiceGroups: GroupSet{"scrapers": true},
		},
	}
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	routes := []Route{
		{Name: RouteNameScheduler, Method: http.MethodGet, Pattern: "/ws/v1/partitions", HandlerFunc: ok},
		{Name: RouteNameCluster, Method: http.MethodGet, Pattern: "/ws/v1/config", HandlerFunc: ok},
		{Name: RouteNameMetrics, Method: http.MethodGet, Pattern: "/ws/v1/metrics", HandlerFunc: ok},
		{Name: "Unknown", Method: http.MethodGet, Pattern: "/custom", HandlerFunc: ok},
	}
	handler := NewWebServer(cfg, ":0", routes).Handler()

	do := func(groups []string, path string) int {
		token := signToken(secret, tokenPayload{User: "u", Exp: time.Now().Add(time.Hour).Unix(), Groups: groups})
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: "YK_AUTH", Value: token})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// admin: every known category; unknown categories are never served
	assert.Equal(t, do([]string{"admins"}, "/ws/v1/partitions"), http.StatusNoContent)
	assert.Equal(t, do([]string{"admins"}, "/ws/v1/config"), http.StatusNoContent)
	assert.Equal(t, do([]string{"admins"}, "/ws/v1/metrics"), http.StatusNoContent)
	assert.Equal(t, do([]string{"admins"}, "/custom"), http.StatusForbidden)

	// viewer: the Scheduler routes only
	assert.Equal(t, do([]string{"viewers"}, "/ws/v1/partitions"), http.StatusNoContent)
	assert.Equal(t, do([]string{"viewers"}, "/ws/v1/config"), http.StatusForbidden)
	assert.Equal(t, do([]string{"viewers"}, "/ws/v1/metrics"), http.StatusForbidden)

	// service: the Metrics routes only
	assert.Equal(t, do([]string{"scrapers"}, "/ws/v1/metrics"), http.StatusNoContent)
	assert.Equal(t, do([]string{"scrapers"}, "/ws/v1/partitions"), http.StatusForbidden)

	// no configured role: rejected
	assert.Equal(t, do([]string{"strangers"}, "/ws/v1/partitions"), http.StatusForbidden)

	// without authentication configured, unknown categories are served as-is
	open := NewWebServer(&Config{}, ":0", []Route{
		{Name: "Unknown", Method: http.MethodGet, Pattern: "/custom", HandlerFunc: ok},
	}).Handler()
	rr := httptest.NewRecorder()
	open.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/custom", nil))
	assert.Equal(t, rr.Code, http.StatusNoContent)
}

func TestCookieAuthExpired(t *testing.T) {
	secret := "test-secret"
	cfg := &Config{
		Mode:         AuthModeLDAP,
		SharedSecret: secret,
	}
	token := signToken(secret, tokenPayload{
		User: "expired",
		Exp:  time.Now().Add(-time.Hour).Unix(),
	})

	handler := cfg.cookieAuth(cfg.ldapBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "YK_AUTH", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// Expired cookie should fall through to Basic (which we didn't provide) -> 401
	assert.Equal(t, rr.Code, http.StatusUnauthorized)
}

func TestCookieAuthInvalidSig(t *testing.T) {
	secret := "test-secret"
	cfg := &Config{
		Mode:         AuthModeLDAP,
		SharedSecret: secret,
	}
	// token with wrong secret
	token := signToken("wrong-secret", tokenPayload{
		User: "hacker",
		Exp:  time.Now().Add(time.Hour).Unix(),
	})

	handler := cfg.cookieAuth(cfg.ldapBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "YK_AUTH", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusUnauthorized)
}

// ----------------- Group cache tests -----------------
func TestGroupCache(t *testing.T) {
	cache := newGroupCache(50 * time.Millisecond)
	groups := map[string]bool{"a": true, "b": true}
	cache.set("user1", groups)

	retrieved, ok := cache.get("user1")
	assert.Assert(t, ok)
	assert.DeepEqual(t, retrieved, groups)

	// expiry
	time.Sleep(60 * time.Millisecond)
	_, ok = cache.get("user1")
	assert.Assert(t, !ok)
}

// ----------------- Helper function tests -----------------
func TestNormalizeGroupName(t *testing.T) {
	assert.Equal(t, "admin", normalizeGroupName(" Admin "))
	assert.Equal(t, "admin", normalizeGroupName("ADMIN"))
}

func TestParsePrincipalUser(t *testing.T) {
	assert.Equal(t, "user", parsePrincipalUser("user@REALM"))
	assert.Equal(t, "user", parsePrincipalUser("user"))
}

func TestLoadConfigTLS(t *testing.T) {
	// no TLS variables set: no TLS sections, plain HTTP
	cfg, err := LoadConfig()
	assert.NilError(t, err)
	assert.Assert(t, cfg.TLS == nil)
	assert.Assert(t, cfg.K8Shim.TLS == nil)

	certFile, keyFile := writeTestCertificate(t)

	// listener certificates for the webservice itself
	t.Setenv("YUNIKORN_TLS_CERT_FILE", certFile)
	t.Setenv("YUNIKORN_TLS_KEY_FILE", keyFile)
	// client certificates for the web -> k8shim mTLS connection
	t.Setenv("YUNIKORN_K8SHIM_TLS_CERT_FILE", certFile)
	t.Setenv("YUNIKORN_K8SHIM_TLS_KEY_FILE", keyFile)
	t.Setenv("YUNIKORN_K8SHIM_TLS_CA_FILE", certFile)

	cfg, err = LoadConfig()
	assert.NilError(t, err)
	assert.Assert(t, cfg.TLS != nil)
	tlsCfg, err := cfg.TLS.TLSConfig()
	assert.NilError(t, err)
	assert.Equal(t, len(tlsCfg.Certificates), 1)
	assert.Assert(t, tlsCfg.ClientCAs == nil)

	assert.Assert(t, cfg.K8Shim.TLS != nil)
	shimTLS, err := cfg.K8Shim.TLS.TLSConfig()
	assert.NilError(t, err)
	assert.Equal(t, len(shimTLS.Certificates), 1)
	assert.Assert(t, shimTLS.RootCAs != nil)

	// listener CA file: pool for client certificate verification
	t.Setenv("YUNIKORN_TLS_CA_FILE", certFile)
	cfg, err = LoadConfig()
	assert.NilError(t, err)
	tlsCfg, err = cfg.TLS.TLSConfig()
	assert.NilError(t, err)
	assert.Assert(t, tlsCfg.ClientCAs != nil)

	// the mtls auth mode enforces client certificates on top of the loaded config
	mtlsCfg := &Config{Mode: AuthModeMTLS, TLS: cfg.TLS}
	tlsCfg, err = mtlsCfg.TLSConfig()
	assert.NilError(t, err)
	assert.Equal(t, tlsCfg.ClientAuth, tls.RequireAndVerifyClientCert)

	// broken configuration surfaces an error
	t.Setenv("YUNIKORN_TLS_CERT_FILE", filepath.Join(t.TempDir(), "missing.crt"))
	cfg, err = LoadConfig()
	assert.NilError(t, err)
	_, err = cfg.TLS.TLSConfig()
	assert.ErrorContains(t, err, "TLS key pair")

	// cert without key is rejected
	t.Setenv("YUNIKORN_TLS_CERT_FILE", certFile)
	t.Setenv("YUNIKORN_TLS_KEY_FILE", "")
	cfg, err = LoadConfig()
	assert.NilError(t, err)
	_, err = cfg.TLS.TLSConfig()
	assert.ErrorContains(t, err, "both")
}

func TestLoadConfigAuth(t *testing.T) {
	// no auth variables set: authentication disabled
	cfg, err := LoadConfig()
	assert.NilError(t, err)
	assert.Equal(t, cfg.Mode, AuthMode(""))

	t.Setenv("YUNIKORN_AUTH_MODE", string(AuthModeSharedSecret))
	t.Setenv("YUNIKORN_AUTH_SHARED_SECRET", "secret")
	t.Setenv("YUNIKORN_KEYTAB_PATH", "/etc/krb5.keytab")
	t.Setenv("YUNIKORN_K8SHIM_AUTH_SHARED_SECRET", "proxy-secret")
	t.Setenv("YUNIKORN_LISTEN_ADDRESS", ":8443")

	cfg, err = LoadConfig()
	assert.NilError(t, err)
	assert.Equal(t, cfg.Mode, AuthModeSharedSecret)
	assert.Equal(t, cfg.SharedSecret, "secret")
	assert.Equal(t, cfg.KeytabPath, "/etc/krb5.keytab")
	assert.Equal(t, cfg.ListenAddress, ":8443")
	assert.Equal(t, cfg.K8Shim.URL, "http://127.0.0.1:9080")
	assert.Equal(t, cfg.K8Shim.SharedSecret, "proxy-secret")
}

// writeTestCertificate writes a self-signed certificate and key into a temp dir
// and returns their paths.
func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err, "failed to generate key")
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "yunikorn-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	assert.NilError(t, err, "failed to create certificate")
	keyDER, err := x509.MarshalECPrivateKey(key)
	assert.NilError(t, err, "failed to marshal key")

	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	assert.NilError(t, os.WriteFile(certFile, certPEM, 0o600), "failed to write cert")
	assert.NilError(t, os.WriteFile(keyFile, keyPEM, 0o600), "failed to write key")
	return certFile, keyFile
}

func TestLoadConfigMetricsAuthOverride(t *testing.T) {
	t.Setenv("YUNIKORN_AUTH_MODE", string(AuthModeSharedSecret))
	t.Setenv("YUNIKORN_AUTH_SHARED_SECRET", "main")

	// no override: metrics inherit the main authentication
	cfg, err := LoadConfig()
	assert.NilError(t, err)
	m := cfg.MetricsConfig()
	assert.Equal(t, m.Mode, AuthModeSharedSecret)
	assert.Equal(t, m.SharedSecret, "main")

	// none disables authentication for metrics only
	t.Setenv("YUNIKORN_METRICS_AUTH_MODE", string(AuthModeNone))
	cfg, err = LoadConfig()
	assert.NilError(t, err)
	m = cfg.MetricsConfig()
	assert.Equal(t, m.Mode, AuthMode(""))
	assert.Equal(t, len(m.Middlewares()), 0)
	assert.Equal(t, cfg.Mode, AuthModeSharedSecret)

	// a dedicated mode and secret for metrics
	t.Setenv("YUNIKORN_METRICS_AUTH_MODE", string(AuthModeSharedSecret))
	t.Setenv("YUNIKORN_METRICS_AUTH_SHARED_SECRET", "scrape")
	cfg, err = LoadConfig()
	assert.NilError(t, err)
	m = cfg.MetricsConfig()
	assert.Equal(t, m.Mode, AuthModeSharedSecret)
	assert.Equal(t, m.SharedSecret, "scrape")
	// the main configuration is untouched
	assert.Equal(t, cfg.Mode, AuthModeSharedSecret)
	assert.Equal(t, cfg.SharedSecret, "main")
}

func TestNormalizeLDAPGroupNames(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected []string
	}{
		{
			// the AD default: memberOf yields a DN, which must also produce
			// the short name an operator can configure
			name:     "AD group DN",
			raw:      "CN=Enterprise Admins,CN=Users,DC=adh,DC=local",
			expected: []string{"enterprise admins"},
		},
		{
			// FreeIPA and OpenLDAP group DNs derive their short name too
			name:     "FreeIPA group DN",
			raw:      "cn=admins,cn=groups,cn=accounts,dc=example,dc=com",
			expected: []string{"admins"},
		},
		{
			// the DN is parsed, not split: the escaped comma stays inside the
			// value instead of cutting the name in two
			name:     "escaped comma",
			raw:      `CN=Smith\, John,OU=x,DC=y`,
			expected: []string{"smith, john"},
		},
		{
			// the group entry lookup and memberUid produce plain names
			name:     "already short",
			raw:      "admins",
			expected: []string{"admins"},
		},
		{
			name:     "empty",
			raw:      "",
			expected: []string{""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.DeepEqual(t, normalizeLDAPGroupNames(tt.raw), tt.expected)
		})
	}
}
