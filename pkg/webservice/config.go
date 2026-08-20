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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the single source of environment driven configuration for the
// webservice and the components embedding it (the web UI proxy and k8shim).
// Every environment variable is declared and read here — all of them carry the
// YUNIKORN_ prefix — and the rest of the code only consumes this struct. It
// also carries the authentication settings and implements the authentication
// middleware (see auth.go).
type Config struct {
	// ListenAddress is the address of the yunikorn-web listener (the core
	// webservice always serves on :9080).
	ListenAddress string `env:"LISTEN_ADDRESS" envDefault:":9889"`
	KeytabPath    string `env:"KEYTAB_PATH"`

	// Authentication settings for the user facing leg (user -> web, or the
	// clients of the k8shim listener). Mode is inferred from the configured
	// secret when not set explicitly; an empty Mode after LoadConfig means
	// authentication is disabled (a configured keytab still enforces SPNEGO).
	Mode         AuthMode `env:"AUTH_MODE"`
	SharedSecret string   `env:"AUTH_SHARED_SECRET"`
	UseXGroups   bool     `env:"USE_X_GROUPS"`

	// MetricsAuth optionally overrides the authentication for the /metrics
	// endpoint of the metrics-only listener: an empty mode inherits the main
	// settings, `none` disables authentication for metrics.
	MetricsAuth MetricsAuthConfig `envPrefix:"METRICS_"`

	// LDAP is the LDAP connection (including its CA certificate) used for the
	// ldap auth mode and for group based authorization.
	LDAP *LDAPConfig `envPrefix:"LDAP_"`

	// TLS is the server certificate set of the webservice listener; its CA file
	// is used to verify client certificates in the mtls auth mode.
	TLS *TLSConfig `envPrefix:"TLS_"`

	// K8Shim is the web -> k8shim leg: how yunikorn-web reaches the k8shim
	// REST API and authenticates to it.
	K8Shim K8ShimConfig `envPrefix:"K8SHIM_"`
}

// LDAPConfig is the LDAP section of Config: connection settings (including the
// CA certificate of the directory server) and the role group mappings.
type LDAPConfig struct {
	URL                string        `env:"URL"`
	BindDN             string        `env:"BIND_DN"`
	BindPassword       string        `env:"BIND_PASSWORD"`
	BaseDN             string        `env:"BASE_DN"`
	UserBaseDN         string        `env:"USER_BASE_DN"`
	GroupAttribute     string        `env:"GROUP_ATTRIBUTE"`
	AllowedGroups      GroupSet      `env:"ALLOWED_GROUPS"`
	AdminGroups        GroupSet      `env:"ADMIN_GROUPS"`
	ViewerGroups       GroupSet      `env:"VIEWER_GROUPS"`
	ServiceGroups      GroupSet      `env:"SERVICE_GROUPS"`
	CacheTTL           time.Duration `env:"CACHE_TTL"`
	InsecureSkipVerify bool          `env:"INSECURE_SKIP_VERIFY"`
	CAFile             string        `env:"CA_FILE"`
	CookieTTL          time.Duration `env:"COOKIE_TTL"`
	CookieSecret       string        `env:"COOKIE_SECRET"`

	// internal global group cache (initialised once)
	cache *groupCache
}

// MetricsAuthConfig is the authentication override for the /metrics endpoint.
type MetricsAuthConfig struct {
	Mode         AuthMode `env:"AUTH_MODE"`
	SharedSecret string   `env:"AUTH_SHARED_SECRET"`
}

// MetricsConfig returns the configuration effective for the metrics-only
// listener: the main configuration with the YUNIKORN_METRICS_AUTH_* override
// applied. An empty override inherits the main authentication settings, the
// `none` mode disables authentication for metrics.
func (cfg *Config) MetricsConfig() *Config {
	if cfg == nil {
		return nil
	}
	out := *cfg
	switch cfg.MetricsAuth.Mode {
	case "":
		// inherit the main mode
	case AuthModeNone:
		out.Mode = ""
		// an empty mode with a keytab still enforces SPNEGO, clear it too
		out.KeytabPath = ""
	default:
		if mode := parseAuthMode(string(cfg.MetricsAuth.Mode)); mode != "" {
			out.Mode = mode
		}
	}
	if cfg.MetricsAuth.SharedSecret != "" {
		out.SharedSecret = cfg.MetricsAuth.SharedSecret
	}
	return &out
}

// GroupSet is a comma separated list of group names in the environment,
// normalized into a lowercase lookup set.
type GroupSet map[string]bool

func (g *GroupSet) UnmarshalText(text []byte) error {
	set := make(map[string]bool)
	for part := range strings.SplitSeq(string(text), ",") {
		if s := strings.TrimSpace(part); s != "" {
			set[strings.ToLower(s)] = true
		}
	}
	*g = set
	return nil
}

// K8ShimConfig configures the web -> k8shim leg: the REST API address, the
// secret used to sign the tokens the proxy attaches to forwarded requests
// (the k8shim listener validates them in its shared_secret mode) and the
// client certificate set for mTLS between web and k8shim.
type K8ShimConfig struct {
	URL          string     `env:"URL" envDefault:"http://127.0.0.1:9080"`
	SharedSecret string     `env:"AUTH_SHARED_SECRET"`
	TLS          *TLSConfig `envPrefix:"TLS_"`
}

// TLSConfig is a reusable certificate file set: server certificates for the
// webservice listener or client certificates for the web to k8shim connection.
type TLSConfig struct {
	CertFile string `env:"CERT_FILE"`
	KeyFile  string `env:"KEY_FILE"`
	CAFile   string `env:"CA_FILE"`
}

// LoadConfig reads the whole webservice configuration from the environment.
func LoadConfig() (*Config, error) {
	// nested struct pointers must exist before parsing: env.Parse does not
	// descend into nil pointers
	cfg := &Config{
		LDAP:   &LDAPConfig{},
		TLS:    &TLSConfig{},
		K8Shim: K8ShimConfig{TLS: &TLSConfig{}},
	}

	if err := env.ParseWithOptions(cfg, env.Options{Prefix: "YUNIKORN_"}); err != nil {
		return nil, err
	}
	// keep the pointers nil when the corresponding variables are not set

	if cfg.TLS.IsZero() {
		cfg.TLS = nil
	}

	if cfg.K8Shim.TLS.IsZero() {
		cfg.K8Shim.TLS = nil
	}
	cfg.normalizeAuth()
	return cfg, nil
}

// normalizeAuth finalizes the parsed authentication settings: it infers the
// mode from the configured secret and wires the LDAP section. An empty Mode
// after normalization means authentication is disabled.
func (cfg *Config) normalizeAuth() {
	if cfg.LDAP.IsZero() {
		cfg.LDAP = nil
	} else {
		cfg.LDAP.applyDefaults()
	}

	mode := parseAuthMode(string(cfg.Mode))
	if mode == "" && cfg.Mode == "" && cfg.SharedSecret != "" {
		// no explicit mode: infer shared_secret from the configured secret
		mode = AuthModeSharedSecret
	}
	// an unknown explicit mode disables authentication as well
	cfg.Mode = mode
	if cfg.Mode == AuthModeLDAP && cfg.LDAP != nil && cfg.LDAP.CookieSecret != "" {
		// the LDAP cookie secret takes precedence for cookie signing
		cfg.SharedSecret = cfg.LDAP.CookieSecret
	}
}

func (c LDAPConfig) IsZero() bool {
	return c.URL == "" && c.BindDN == "" && c.BindPassword == "" && c.BaseDN == "" &&
		c.GroupAttribute == "" && c.CAFile == "" && c.CookieSecret == "" &&
		len(c.AllowedGroups) == 0 && len(c.AdminGroups) == 0 &&
		len(c.ViewerGroups) == 0 && len(c.ServiceGroups) == 0 &&
		c.CacheTTL == 0 && c.CookieTTL == 0 && !c.InsecureSkipVerify
}

func (c *LDAPConfig) applyDefaults() {
	if c.GroupAttribute == "" {
		c.GroupAttribute = "memberOf"
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = 5 * time.Minute
	}
	if c.CookieTTL <= 0 {
		c.CookieTTL = time.Hour
	}
	// initialise global group cache
	c.cache = newGroupCache(c.CacheTTL)
}

// TLSConfig builds the TLS configuration of the webservice listener from the
// TLS section; in the mtls auth mode client certificates are additionally
// required and verified. It returns nil when TLS is not configured and the
// mtls mode is not active, so the listener serves plain HTTP.
func (cfg *Config) TLSConfig() (*tls.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	var tlsCfg *tls.Config
	if cfg.TLS != nil {
		var err error
		tlsCfg, err = cfg.TLS.TLSConfig()
		if err != nil {
			return nil, err
		}
	}
	if cfg.Mode == AuthModeMTLS {
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

func (c TLSConfig) IsZero() bool {
	return c.CertFile == "" && c.KeyFile == "" && c.CAFile == ""
}

// TLSConfig builds a *tls.Config from the configured files. It returns nil when
// nothing is configured. The CA pool is set both as RootCAs (client side, e.g.
// web verifying the k8shim server certificate) and ClientCAs (server side,
// verifying client certificates in the mtls auth mode).
func (c TLSConfig) TLSConfig() (*tls.Config, error) {
	if c.IsZero() {
		return nil, nil
	}
	cfg := &tls.Config{}
	if c.CertFile != "" || c.KeyFile != "" {
		if c.CertFile == "" || c.KeyFile == "" {
			return nil, fmt.Errorf("TLS certificate and key files must both be set")
		}
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("unable to load TLS key pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if c.CAFile != "" {
		caCert, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read TLS CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("no certificates found in TLS CA file %s", c.CAFile)
		}
		cfg.RootCAs = pool
		cfg.ClientCAs = pool
	}
	return cfg, nil
}
