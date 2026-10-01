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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

func ldapConfig(secret string) *Config {
	return &Config{
		Mode:         AuthModeLDAP,
		SharedSecret: secret,
		LDAP: &LDAPConfig{
			AdminGroups: GroupSet{"admins": true},
			CookieTTL:   time.Hour,
		},
	}
}

func authTestRoutes() []Route {
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	return []Route{
		{Name: RouteNameScheduler, Method: http.MethodGet, Pattern: "/ws/v1/partitions", HandlerFunc: ok},
		{Name: RouteNameAuth, Method: http.MethodGet, Pattern: "/auth/whoami", HandlerFunc: ok},
		{Name: RouteNameStaticUI, Method: http.MethodGet, Pattern: "/*filepath", HandlerFunc: ok},
	}
}

func get(handler http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func authCookie(secret, user string, groups []string) *http.Cookie {
	return &http.Cookie{Name: "YK_AUTH", Value: signToken(secret, tokenPayload{
		User: user, Exp: time.Now().Add(time.Hour).Unix(), Groups: groups,
	})}
}

// TestPublicRoutesInLDAPMode: the UI and the auth endpoints are served without
// a session, the scheduler API is not, and a role is only checked on the API.
func TestPublicRoutesInLDAPMode(t *testing.T) {
	secret := "test-secret"
	handler := NewWebServer(ldapConfig(secret), ":0", authTestRoutes()).Handler()

	assert.Equal(t, get(handler, "/auth/whoami", nil).Code, http.StatusNoContent)
	assert.Equal(t, get(handler, "/index.html", nil).Code, http.StatusNoContent)

	rr := get(handler, "/ws/v1/partitions", nil)
	assert.Equal(t, rr.Code, http.StatusUnauthorized)
	assert.Equal(t, rr.Header().Get("WWW-Authenticate"), `Basic realm="yunikorn"`)

	admin := authCookie(secret, "alice", []string{"admins"})
	assert.Equal(t, get(handler, "/ws/v1/partitions", admin).Code, http.StatusNoContent)

	// a user outside every role group keeps the auth endpoints and the UI
	stranger := authCookie(secret, "bob", []string{"strangers"})
	assert.Equal(t, get(handler, "/ws/v1/partitions", stranger).Code, http.StatusForbidden)
	assert.Equal(t, get(handler, "/auth/whoami", stranger).Code, http.StatusNoContent)
	assert.Equal(t, get(handler, "/index.html", stranger).Code, http.StatusNoContent)
}

// TestNoPublicRoutesOutsideLDAPMode: nothing is public in the other modes.
func TestNoPublicRoutesOutsideLDAPMode(t *testing.T) {
	handler := NewWebServer(&Config{Mode: AuthModeMTLS}, ":0", authTestRoutes()).Handler()
	for _, path := range []string{"/ws/v1/partitions", "/auth/whoami", "/index.html"} {
		assert.Equal(t, get(handler, path, nil).Code, http.StatusUnauthorized, "path %s", path)
	}
}

// TestUnknownPathIsAuthenticated: without a static UI route a request that
// matches nothing is answered by the router itself.
func TestUnknownPathIsAuthenticated(t *testing.T) {
	secret := "test-secret"
	routes := authTestRoutes()[:1]
	handler := NewWebServer(ldapConfig(secret), ":0", routes).Handler()

	assert.Equal(t, get(handler, "/nowhere", nil).Code, http.StatusUnauthorized)
	assert.Equal(t, get(handler, "/nowhere", authCookie(secret, "alice", nil)).Code, http.StatusNotFound)
}
