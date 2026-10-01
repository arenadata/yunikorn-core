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
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

func sessionConfig() *Config {
	cfg := ldapConfig("session-secret")
	cfg.LDAP.CookieTTL = time.Hour
	cfg.LDAP.SessionMaxLifetime = 4 * time.Hour
	return cfg
}

// TestRenewAuthCookie: an active user keeps the session, an idle one loses it,
// and no renewal reaches past the absolute limit.
func TestRenewAuthCookie(t *testing.T) {
	cfg := sessionConfig()
	now := time.Now()

	t.Run("more than half the TTL left", func(t *testing.T) {
		tp := tokenPayload{User: "alice", Auth: now.Unix(), Exp: now.Add(50 * time.Minute).Unix()}
		assert.Assert(t, cfg.renewAuthCookie(tp) == nil)
	})

	t.Run("less than half the TTL left", func(t *testing.T) {
		tp := tokenPayload{User: "alice", Name: "Alice", Auth: now.Add(-time.Hour).Unix(),
			Exp: now.Add(20 * time.Minute).Unix()}
		cookie := cfg.renewAuthCookie(tp)
		assert.Assert(t, cookie != nil)

		renewed, ok := verifyToken(cfg.SharedSecret, cookie.Value)
		assert.Assert(t, ok)
		assert.Assert(t, renewed.Exp > tp.Exp)
		// the login time and the display name survive the renewal
		assert.Equal(t, renewed.Auth, tp.Auth)
		assert.Equal(t, renewed.Name, "Alice")
	})

	t.Run("not past the session limit", func(t *testing.T) {
		login := now.Add(-3*time.Hour - 30*time.Minute)
		tp := tokenPayload{User: "alice", Auth: login.Unix(), Exp: now.Add(20 * time.Minute).Unix()}
		cookie := cfg.renewAuthCookie(tp)
		assert.Assert(t, cookie != nil)
		assert.Equal(t, cookie.Expires.Unix(), login.Add(cfg.LDAP.SessionMaxLifetime).Unix())

		// at the limit there is nothing left to give
		tp.Exp = cookie.Expires.Unix()
		assert.Assert(t, cfg.renewAuthCookie(tp) == nil)
	})

	t.Run("a cookie issued before the upgrade", func(t *testing.T) {
		tp := tokenPayload{User: "alice", Exp: now.Add(time.Minute).Unix()}
		assert.Assert(t, cfg.renewAuthCookie(tp) == nil)
	})
}

// TestRenewalOnRequest: the renewed cookie comes back with the response, on any
// request that carries the session.
func TestRenewalOnRequest(t *testing.T) {
	cfg := sessionConfig()
	handler := NewWebServer(cfg, ":0", authTestRoutes()).Handler()

	stale := &http.Cookie{Name: "YK_AUTH", Value: signToken(cfg.SharedSecret, tokenPayload{
		User: "alice", Groups: []string{"admins"},
		Auth: time.Now().Add(-time.Hour).Unix(),
		Exp:  time.Now().Add(10 * time.Minute).Unix(),
	})}

	rr := get(handler, "/ws/v1/partitions", stale)
	assert.Equal(t, rr.Code, http.StatusNoContent)
	cookies := rr.Result().Cookies()
	assert.Equal(t, len(cookies), 1)
	assert.Equal(t, cookies[0].Name, "YK_AUTH")
	assert.Assert(t, cookies[0].Expires.After(time.Now().Add(50*time.Minute)))
}

// TestLoginCookieCarriesTheLoginTime: the login time is what caps the renewals.
func TestLoginCookieCarriesTheLoginTime(t *testing.T) {
	cfg := sessionConfig()
	cookie := cfg.newAuthCookie("alice", []string{"admins"}, "Alice")

	tp, ok := verifyToken(cfg.SharedSecret, cookie.Value)
	assert.Assert(t, ok)
	assert.Assert(t, tp.Auth > 0)
	assert.Equal(t, tp.Exp, cookie.Expires.Unix())
}
