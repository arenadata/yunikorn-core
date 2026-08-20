<!--
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 -->
# Apache YuniKorn - A Universal Scheduler

[![Build Status](https://github.com/apache/yunikorn-core/actions/workflows/push-master.yml/badge.svg)](https://github.com/apache/yunikorn-core/actions)
[![codecov](https://codecov.io/gh/apache/yunikorn-core/branch/master/graph/badge.svg)](https://codecov.io/gh/apache/yunikorn-core)
[![Go Report Card](https://goreportcard.com/badge/github.com/apache/yunikorn-core)](https://goreportcard.com/report/github.com/apache/yunikorn-core)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Repo Size](https://img.shields.io/github/repo-size/apache/yunikorn-core)](https://img.shields.io/github/repo-size/apache/yunikorn-core)

Apache YuniKorn is a light-weight, universal resource scheduler for container orchestrator systems.
It is created to achieve fine-grained resource sharing for various workloads efficiently on a large scale, multi-tenant,
and cloud-native environment. YuniKorn brings a unified, cross-platform, scheduling experience for mixed workloads that consist
of stateless batch workloads and stateful services. 

YuniKorn now supports K8s and can be deployed as a custom K8s scheduler. YuniKorn's architecture design also allows adding different
shim layer and adopt to different ResourceManager implementation including Apache Hadoop YARN, or any other systems.

## Get Started

See how to get started with running YuniKorn on Kubernetes, please read the documentation on [yunikorn.apache.org](http://yunikorn.apache.org/docs/).

Want to know more about the value of the YuniKorn project, and what YuniKorn can do? Here are some
[session recordings and demos](https://yunikorn.apache.org/community/events#past-conference--meetup-recordings).

## Get Involved

Please read [get involved](http://yunikorn.apache.org/community/get_involved) document if you want to discuss issues,
contribute your ideas, explore use cases, or participate the development.

If you want to contribute code to this repo, please read the [developer doc](http://yunikorn.apache.org/docs/next/developer_guide/build).
All the design docs are available [here](http://yunikorn.apache.org/docs/next/design/architecture).

## Code Structure

Apache YuniKorn project has the following git repositories:

- [yunikorn-core](https://github.com/apache/yunikorn-core/) : the scheduler brain :round_pushpin: 
- [yunikorn-k8shim](https://github.com/apache/yunikorn-k8shim) : the adaptor to Kubernetes
- [yunikorn-scheduler-interface](https://github.com/apache/yunikorn-scheduler-interface) : the common scheduling interface
- [yunikorn-web](https://github.com/apache/yunikorn-web) : the web UI
- [yunikorn-release](https://github.com/apache/yunikorn-release/): the repo manages yunikorn releases, including the helm charts
- [yunikorn-site](https://github.com/apache/yunikorn-site/): the source code for [yunikorn website](http://yunikorn.apache.org/)

The `yunikorn-core` is the brain of the scheduler, which makes placement decisions (allocate container X on node Y) according
to the builtin rich scheduling policies. Scheduler core implementation is agnostic to the underneath resource manager system.

## Webservice

The `pkg/webservice` package provides the single shared web server used by all
YuniKorn web components: an `httprouter` serving a route table, wrapped with
the authentication middleware chain, response compression and listener TLS. A
route with the root catch-all pattern `/*filepath` (e.g. the static UI file
server) becomes the fallback for every path no other route matched. The
scheduler REST API (`:9080`) and the `yunikorn-web` UI server are both built
on it and differ only in the routes and middleware they register.

The whole configuration is read from environment variables in a single place —
the `webservice.Config` type (`webservice.LoadConfig()`). All variables carry
the `YUNIKORN_` prefix.

## Authentication and authorization (Auth)

Authentication is split into two independent legs:

- **user -> web** (or any client of the scheduler REST API): the listener
	authentication configured with `YUNIKORN_AUTH_MODE`;
- **web -> k8shim**: how the `yunikorn-web` proxy authenticates to the k8shim
	REST API, configured with the `YUNIKORN_K8SHIM_*` variables on the web side.
	The user's `Authorization` header is never forwarded: when
	`YUNIKORN_K8SHIM_AUTH_SHARED_SECRET` is set, the proxy attaches a token
	signed from the authenticated request identity, which the k8shim listener
	validates in its `shared_secret` mode.

Supported `YUNIKORN_AUTH_MODE` values (empty means authentication is
disabled; `shared_secret` is inferred when only the secret is set):

- `mtls`: mutual TLS authentication — a verified client certificate is
	required (the listener CA is set with `YUNIKORN_TLS_CA_FILE`).
- `shared_secret`: HMAC-signed token in the `Authorization: Token <token>`
	header; the shared secret (`YUNIKORN_AUTH_SHARED_SECRET`) is only used to
	sign and verify the token. The token format is
	`<base64(payload)>.<hex(hmac_sha256(payload))>`, where the payload is JSON:
	`{ "user": "<user>", "exp": <unix_ts>, "groups": ["g1","g2"] }`.
- `ldap`: BasicAuth password verification against LDAP; on success the server
	issues a secure `YK_AUTH` cookie with the same token format, signed with the
	shared secret (or `YUNIKORN_LDAP_COOKIE_SECRET`); the TTL is configured via
	`YUNIKORN_LDAP_COOKIE_TTL`.
- `kerberos` / `kerberos_ldap`: SPNEGO (Kerberos) via a keytab
	(`YUNIKORN_KEYTAB_PATH`); `kerberos_ldap` additionally authorizes via LDAP
	group lookups.

Every mode is implemented as a chain of single purpose middleware
(`webservice.Middleware`, see `Config.Middlewares()`); role based
authorization is applied per route, driven by the route category (the `Name`
of the `webservice.Route`: `Cluster`, `Scheduler`, `Metrics`, `System`,
`StaticUI`).

Role based authorization (LDAP):
- Groups configured in `YUNIKORN_LDAP_ADMIN_GROUPS`, `YUNIKORN_LDAP_VIEWER_GROUPS`
	and `YUNIKORN_LDAP_SERVICE_GROUPS` map to the `admin`, `viewer` and `service`
	roles. The roles restrict access by route category:
	- `admin`: every category
	- `viewer`: the `Scheduler` routes only (for example `/ws/v1/partitions`)
	- `service`: the `Metrics` routes only (`/ws/v1/metrics` of the REST API and
		`/metrics` of the metrics-only listener)
- `YUNIKORN_LDAP_ALLOWED_GROUPS` grants plain access without a role.
- With authentication enabled, routes with a category outside the list above
	are not served at all — they respond with 403.
- The `X-Groups` header can be enabled (`YUNIKORN_USE_X_GROUPS`) to inject
	groups provided by an upstream proxy into the request identity.

Certificates come in three independent sets:

- the webservice listener — `YUNIKORN_TLS_CERT_FILE`, `YUNIKORN_TLS_KEY_FILE`
	and optionally `YUNIKORN_TLS_CA_FILE` (the CA used to verify client
	certificates in the `mtls` auth mode); without these variables the server
	serves plain HTTP;
- the LDAP connection — `YUNIKORN_LDAP_CA_FILE` (and `YUNIKORN_LDAP_INSECURE_SKIP_VERIFY`);
- mTLS between yunikorn-web and yunikorn-k8shim — the client certificate set
	`YUNIKORN_K8SHIM_TLS_CERT_FILE`, `YUNIKORN_K8SHIM_TLS_KEY_FILE`,
	`YUNIKORN_K8SHIM_TLS_CA_FILE` (set on the yunikorn-web side together with
	`YUNIKORN_K8SHIM_URL`).

Environment variable reference:

| Variable | Purpose |
|----------|---------|
| `YUNIKORN_LISTEN_ADDRESS` | yunikorn-web listen address (default `:9889`; the scheduler REST API always serves on `:9080`) |
| `YUNIKORN_AUTH_MODE` | user facing authentication mode: `mtls`, `shared_secret`, `ldap`, `kerberos`, `kerberos_ldap` |
| `YUNIKORN_AUTH_SHARED_SECRET` | secret signing/verifying the tokens of the user facing leg |
| `YUNIKORN_KEYTAB_PATH` | keytab for SPNEGO (kerberos modes) |
| `YUNIKORN_USE_X_GROUPS` | enable group injection via the `X-Groups` header |
| `YUNIKORN_METRICS_AUTH_MODE` | authentication override for the `/metrics` endpoint of the metrics-only listener: an auth mode, or `none` to disable; empty inherits the main settings |
| `YUNIKORN_METRICS_AUTH_SHARED_SECRET` | dedicated secret for the `/metrics` override |
| `YUNIKORN_TLS_CERT_FILE` / `_KEY_FILE` / `_CA_FILE` | listener TLS certificate set |
| `YUNIKORN_LDAP_USER_BASE_DN` | subtree holding user entries; defaults to `_BASE_DN` |
| `YUNIKORN_LDAP_URL`, `_BIND_DN`, `_BIND_PASSWORD`, `_BASE_DN` | LDAP connection and service account |
| `YUNIKORN_LDAP_GROUP_ATTRIBUTE` | group attribute (default `memberOf`) |
| `YUNIKORN_LDAP_ALLOWED_GROUPS`, `_ADMIN_GROUPS`, `_VIEWER_GROUPS`, `_SERVICE_GROUPS` | comma separated group lists for authorization |
| `YUNIKORN_LDAP_CACHE_TTL` | group membership cache TTL (default `5m`) |
| `YUNIKORN_LDAP_CA_FILE`, `YUNIKORN_LDAP_INSECURE_SKIP_VERIFY` | LDAP connection TLS |
| `YUNIKORN_LDAP_COOKIE_SECRET`, `YUNIKORN_LDAP_COOKIE_TTL` | `YK_AUTH` cookie signing secret and TTL (default `1h`) |
| `YUNIKORN_K8SHIM_URL` | k8shim REST API address (web side, default `http://127.0.0.1:9080`) |
| `YUNIKORN_K8SHIM_AUTH_SHARED_SECRET` | secret signing the tokens of the web -> k8shim leg |
| `YUNIKORN_K8SHIM_TLS_CERT_FILE` / `_KEY_FILE` / `_CA_FILE` | client certificate set for mTLS between web and k8shim |

For token formats and middleware behaviour see the comments in
[pkg/webservice/auth.go](pkg/webservice/auth.go).
