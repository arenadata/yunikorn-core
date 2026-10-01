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
	"io"
	"mime"
	"net/http"

	"go.uber.org/zap"

	"github.com/go-krb5/x/identity"

	"github.com/apache/yunikorn-core/pkg/log"
)

// maxLoginBodyBytes caps the login body: the credentials are two short strings.
const maxLoginBodyBytes = 4 << 10

// loginRequest is the body of POST /auth/login.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// whoamiResponse is the body of GET /auth/whoami; User is empty without a session.
type whoamiResponse struct {
	Mode        string `json:"mode"`
	User        string `json:"user"`
	DisplayName string `json:"displayName"`
}

// AuthRoutes returns the /auth endpoints of yunikorn-web. They are a separate
// set, so that the scheduler listener does not serve them and the web proxy
// does not mirror them. Only the ldap mode has a session to start and end.
func AuthRoutes(cfg *Config) []Route {
	routes := []Route{
		{Name: RouteNameAuth, Method: http.MethodGet, Pattern: "/auth/whoami", HandlerFunc: whoami(cfg)},
	}
	if cfg != nil && cfg.Mode == AuthModeLDAP {
		routes = append(routes,
			Route{Name: RouteNameAuth, Method: http.MethodPost, Pattern: "/auth/login", HandlerFunc: login(cfg)},
			Route{Name: RouteNameAuth, Method: http.MethodPost, Pattern: "/auth/logout", HandlerFunc: logout()},
		)
	}
	return routes
}

// authError answers with a JSON error: buildJSONErrorResponse writes the body
// but does not announce its type.
func authError(w http.ResponseWriter, detail string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	buildJSONErrorResponse(w, detail, code)
}

// login binds the credentials against LDAP and sets the same cookie as Basic
// auth. It sends no WWW-Authenticate: the SPA shows its own form.
func login(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// an HTML form cannot send this content type, which keeps a cross-site
		// page from logging the user in
		if contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || contentType != "application/json" {
			authError(w, "Invalid content type", http.StatusBadRequest)
			return
		}
		var req loginRequest
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxLoginBodyBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			authError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if req.Username == "" || req.Password == "" {
			authError(w, "Authentication failed", http.StatusUnauthorized)
			return
		}
		groups, displayName, err := cfg.ldapBind(req.Username, req.Password)
		if err != nil {
			authError(w, "Authentication failed", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, cfg.newAuthCookie(req.Username, groups, displayName))
		w.WriteHeader(http.StatusNoContent)
	}
}

// logout expires the cookie in the browser. The server keeps no session state,
// so a copy of the cookie taken earlier stays valid until it expires.
func logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, expireAuthCookie())
		w.WriteHeader(http.StatusNoContent)
	}
}

// whoami reports the enforced mode and, with a session, who it belongs to. The
// SPA reads the mode from here, so it answers without a session as well.
func whoami(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mode := cfg.enforcedMode()
		resp := whoamiResponse{Mode: string(mode)}
		if id := identity.FromHTTPRequestContext(r); id != nil {
			resp.User = id.UserName()
			if id.Domain() != "" {
				resp.User += "@" + id.Domain()
			}
			// a Kerberos identity carries a short name of its own, while the UI
			// shows the principal
			resp.DisplayName = resp.User
			if mode == AuthModeLDAP && id.DisplayName() != "" {
				resp.DisplayName = id.DisplayName()
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		// the answer depends on the session, so a cached copy would keep showing
		// the user after a logout
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Log(log.REST).Error("unable to write the whoami response", zap.Error(err))
		}
	}
}
