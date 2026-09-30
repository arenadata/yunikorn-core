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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/x/identity"
	"gotest.tools/v3/assert"
)

func whoamiOf(t *testing.T, handler http.Handler, cookie *http.Cookie) whoamiResponse {
	t.Helper()
	rr := get(handler, "/auth/whoami", cookie)
	assert.Equal(t, rr.Code, http.StatusOK)
	var resp whoamiResponse
	assert.NilError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}

// TestWhoami: the mode is always reported, the user only with a session, and
// the display name comes from the cookie the bind issued.
func TestWhoami(t *testing.T) {
	secret := "whoami-secret"
	cfg := ldapConfig(secret)
	handler := NewWebServer(cfg, ":0", AuthRoutes(cfg)).Handler()

	assert.DeepEqual(t, whoamiOf(t, handler, nil), whoamiResponse{Mode: "ldap"})

	named := &http.Cookie{Name: "YK_AUTH", Value: signToken(secret, tokenPayload{
		User: "alice", Exp: time.Now().Add(time.Hour).Unix(), Name: "Alice Smith",
	})}
	assert.DeepEqual(t, whoamiOf(t, handler, named),
		whoamiResponse{Mode: "ldap", User: "alice", DisplayName: "Alice Smith"})

	// a cookie issued before the upgrade carries no name
	assert.DeepEqual(t, whoamiOf(t, handler, authCookie(secret, "bob", nil)),
		whoamiResponse{Mode: "ldap", User: "bob", DisplayName: "bob"})
}

// TestWhoamiKerberos reports the principal as both the user and the name.
func TestWhoamiKerberos(t *testing.T) {
	cfg := &Config{KeytabPath: "/etc/keytab"}
	id := newWebIdentity("alice", nil, 0)
	id.SetDomain("EXAMPLE.COM")
	req := identity.AddToHTTPRequestContext(id, httptest.NewRequest(http.MethodGet, "/auth/whoami", nil))
	rr := httptest.NewRecorder()
	whoami(cfg)(rr, req)

	var resp whoamiResponse
	assert.NilError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.DeepEqual(t, resp, whoamiResponse{
		Mode: "kerberos", User: "alice@EXAMPLE.COM", DisplayName: "alice@EXAMPLE.COM",
	})
}

// TestLoginBadRequest: anything that is not a pair of credentials is a 400, and
// the endpoint never challenges with Basic.
func TestLoginBadRequest(t *testing.T) {
	handler := login(ldapConfig("login-secret"))
	for _, body := range []string{``, `not json`, `{"username":"alice","password":"secret","role":"admin"}`} {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.Equal(t, rr.Code, http.StatusBadRequest, "body %q", body)
		assert.Equal(t, rr.Header().Get("Content-Type"), "application/json; charset=UTF-8", "body %q", body)
		assert.Equal(t, rr.Header().Get("WWW-Authenticate"), "", "body %q", body)
	}

	// empty credentials are a failed login, not a malformed request
	for _, body := range []string{`{"username":"alice"}`, `{"username":"alice","password":""}`} {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.Equal(t, rr.Code, http.StatusUnauthorized, "body %q", body)
		assert.Equal(t, rr.Header().Get("WWW-Authenticate"), "", "body %q", body)
	}

	// a form from another site can only send these, so they never reach the bind
	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
		req := httptest.NewRequest(http.MethodPost, "/auth/login",
			strings.NewReader(`{"username":"alice","password":"secret"}`))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.Equal(t, rr.Code, http.StatusBadRequest, "content type %q", contentType)
	}
}

// TestLogout expires the cookie and needs no session of its own.
func TestLogout(t *testing.T) {
	cfg := ldapConfig("logout-secret")
	handler := NewWebServer(cfg, ":0", AuthRoutes(cfg)).Handler()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusNoContent)

	cookies := rr.Result().Cookies()
	assert.Equal(t, len(cookies), 1)
	assert.Equal(t, cookies[0].Name, "YK_AUTH")
	assert.Equal(t, cookies[0].Value, "")
	assert.Equal(t, cookies[0].Path, "/")
	assert.Equal(t, cookies[0].Secure, true)
	assert.Assert(t, strings.Contains(rr.Header().Get("Set-Cookie"), "Max-Age=0"))
}

// TestNoBasicChallenge: the header is what opens the browser dialog, so the
// listener serving the SPA drops it while the scheduler keeps it.
func TestNoBasicChallenge(t *testing.T) {
	routes := authTestRoutes()[:1]

	cfg := ldapConfig("secret")
	rr := get(NewWebServer(cfg, ":0", routes).Handler(), "/ws/v1/partitions", nil)
	assert.Equal(t, rr.Header().Get("WWW-Authenticate"), `Basic realm="yunikorn"`)

	cfg.NoBasicChallenge = true
	rr = get(NewWebServer(cfg, ":0", routes).Handler(), "/ws/v1/partitions", nil)
	assert.Equal(t, rr.Code, http.StatusUnauthorized)
	assert.Equal(t, rr.Header().Get("WWW-Authenticate"), "")
}
