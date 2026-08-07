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
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/julienschmidt/httprouter"

	"go.uber.org/zap"

	"github.com/apache/yunikorn-core/pkg/log"
	"github.com/apache/yunikorn-core/pkg/metrics/history"
	"github.com/apache/yunikorn-core/pkg/scheduler"
)

var imHistory *history.InternalMetricsHistory
var schedulerContext atomic.Pointer[scheduler.ClusterContext]

// WebServer is the shared web server for all YuniKorn web components: an
// httprouter serving a route table (plus an optional static file root), with
// the configured authentication middleware chain, response compression and
// listener TLS applied. The components (the scheduler REST API and the
// yunikorn-web UI) differ only in the routes and middleware they register.
type WebServer struct {
	httpServer *http.Server
}

// NewWebServer builds the shared web server serving the given routes. Role
// based authorization is applied per route, driven by the route Name. A route
// with the root catch-all pattern "/*filepath" (e.g. a static file server)
// becomes the fallback for every path no other route matched: httprouter
// cannot combine a root catch-all with other routes. Extra middleware is
// applied between the authentication chain and the router.
func NewWebServer(cfg *Config, addr string, rts []Route, mw ...Middleware) *WebServer {
	router := httprouter.New()
	for _, rt := range rts {
		handler := cfg.authorizeRoute(rt.Name, loggingHandler(rt.HandlerFunc, rt.Name))
		if rt.Pattern == "/*filepath" {
			router.NotFound = handler
			continue
		}
		router.Handler(rt.Method, rt.Pattern, handler)
	}

	var handler http.Handler = router
	for i := len(mw) - 1; i >= 0; i-- {
		handler = mw[i](handler)
	}

	return &WebServer{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           compressResponse(cfg.Wrap(handler)),
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig:         listenerTLSConfig(cfg),
		},
	}
}

// Handler returns the fully wrapped root handler of the server.
func (ws *WebServer) Handler() http.Handler {
	return ws.httpServer.Handler
}

// Start serves in the background; TLS is used when configured.
func (ws *WebServer) Start() {
	log.Log(log.REST).Info("web server started", zap.String("addr", ws.httpServer.Addr))
	go func() {
		var err error

		if ws.httpServer.TLSConfig == nil {
			err = ws.httpServer.ListenAndServe()
		} else {
			err = ws.httpServer.ListenAndServeTLS("", "")
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Log(log.REST).Error("HTTP serving error",
				zap.Error(err))
		}
	}()
}

// Stop gracefully shuts the server down within 5 seconds.
func (ws *WebServer) Stop() error {
	if ws == nil || ws.httpServer == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ws.httpServer.SetKeepAlivesEnabled(false)
	return ws.httpServer.Shutdown(ctx)
}

func loggingHandler(inner http.Handler, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		inner.ServeHTTP(w, r)
		log.Log(log.REST).Debug("Web router call details",
			zap.String("name", name),
			zap.String("method", r.Method),
			zap.String("uri", r.RequestURI),
			zap.Duration("duration", time.Since(start)))
	}
}

// listenerTLSConfig loads the listener TLS configuration. When TLS is
// configured but broken, a config without certificates is returned: the
// listener then fails to start instead of silently downgrading to plain HTTP.
func listenerTLSConfig(cfg *Config) *tls.Config {
	tlsConfig, err := cfg.TLSConfig()
	if err != nil {
		log.Log(log.REST).Error("unable to load web app TLS configuration, keeping the listener closed",
			zap.Error(err))
		return &tls.Config{}
	}
	return tlsConfig
}

// WebService is the scheduler REST API: the shared web server with the
// scheduler route table.
type WebService struct {
	server *WebServer
}

func NewWebApp(context *scheduler.ClusterContext, internalMetrics *history.InternalMetricsHistory) *WebService {
	m := &WebService{}
	schedulerContext.Store(context)
	imHistory = internalMetrics
	return m
}

// StartWebApp starts the scheduler REST API on the default port.
func (m *WebService) StartWebApp() {
	cfg, err := LoadConfig()
	if err != nil {
		log.Log(log.REST).Error("unable to load webservice configuration",
			zap.Error(err))
		cfg = &Config{}
	}
	m.server = NewWebServer(cfg, ":9080", webRoutes)
	m.server.Start()
}

func (m *WebService) StopWebApp() error {
	return m.server.Stop()
}
