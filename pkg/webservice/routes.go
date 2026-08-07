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
	"net/http/pprof"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type routes []Route

// Route categories. Role based authorization is driven by these names: the
// admin role is allowed everything, viewer the Scheduler routes, service the
// Metrics routes. With authentication enabled, routes with a category not
// listed here are not served at all (403).
const (
	RouteNameCluster   = "Cluster"
	RouteNameScheduler = "Scheduler"
	RouteNameMetrics   = "Metrics"
	RouteNameSystem    = "System"
	// RouteNameStaticUI is the static web UI file server of yunikorn-web.
	RouteNameStaticUI = "StaticUI"
)

// knownRouteName reports whether the route category is one of the defined ones.
func knownRouteName(name string) bool {
	switch name {
	case RouteNameCluster, RouteNameScheduler, RouteNameMetrics, RouteNameSystem, RouteNameStaticUI:
		return true
	}
	return false
}

// Routes returns a copy of the scheduler REST API route table.
func Routes() []Route {
	return append([]Route(nil), webRoutes...)
}

var webRoutes = routes{
	// endpoints to retrieve general cluster info
	Route{
		RouteNameCluster,
		"GET",
		"/ws/v1/clusters",
		getClusterInfo,
	},
	Route{
		RouteNameMetrics,
		"GET",
		"/ws/v1/metrics",
		getMetrics,
	},
	Route{
		RouteNameCluster,
		"GET",
		"/ws/v1/config",
		getClusterConfig,
	},
	Route{
		RouteNameCluster,
		"POST",
		"/ws/v1/validate-conf",
		validateConf,
	},

	// endpoints to retrieve general scheduler info
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/history/apps",
		getApplicationHistory,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/history/containers",
		getContainerHistory,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partitions",
		getPartitions,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/placementrules",
		getPartitionRules,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/queues",
		getPartitionQueues,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/queue/:queue",
		getPartitionQueue,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/nodes",
		getPartitionNodes,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/node/:node",
		getPartitionNode,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/queue/:queue/applications",
		getQueueApplications,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/queue/:queue/application/:application",
		getApplication,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/application/:application",
		getApplication,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/applications/:state",
		getPartitionApplicationsByState,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/queue/:queue/applications/:state",
		getQueueApplicationsByState,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/usage/users",
		getUsersResourceUsage,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/usage/user/:user",
		getUserResourceUsage,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/usage/groups",
		getGroupsResourceUsage,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/partition/:partition/usage/group/:group",
		getGroupResourceUsage,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/events/batch",
		getEvents,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/events/stream",
		getStream,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/scheduler/healthcheck",
		checkHealthStatus,
	},
	Route{
		RouteNameScheduler,
		"GET",
		"/ws/v1/scheduler/node-utilizations",
		getNodeUtilisations,
	},

	// endpoints to retrieve debug info
	//
	// These endpoints are not to be proxied by the web server. The content is not for general consumption.
	// The content is not considered stable and can change from release to release.
	// All pprof endpoints provide profiling data in the format expected by the pprof visualization tool.
	// We need to explicitly register all handlers as we do not use the DefaultServeMux
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/stack",
		HandlerFunc: getStackInfo,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/fullstatedump",
		HandlerFunc: getFullStateDump,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/",
		HandlerFunc: pprof.Index,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/heap",
		HandlerFunc: pprof.Index,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/threadcreate",
		HandlerFunc: pprof.Index,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/goroutine",
		HandlerFunc: pprof.Index,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/allocs",
		HandlerFunc: pprof.Index,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/block",
		HandlerFunc: pprof.Index,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/mutex",
		HandlerFunc: pprof.Index,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/cmdline",
		HandlerFunc: pprof.Cmdline,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/profile",
		HandlerFunc: pprof.Profile,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/symbol",
		HandlerFunc: pprof.Symbol,
	},
	Route{
		Name:        RouteNameSystem,
		Method:      "GET",
		Pattern:     "/debug/pprof/trace",
		HandlerFunc: pprof.Trace,
	},

	// Deprecated REST calls
	//
	// Permanently moved to the debug endpoint as part of YuniKorn 1.7
	// Remove redirect in YuniKorn 1.10
	Route{
		Name:        RouteNameScheduler,
		Method:      "GET",
		Pattern:     "/ws/v1/stack",
		HandlerFunc: redirectDebug,
	},
	// Permanently moved to the debug endpoint as part of YuniKorn 1.7
	// Remove redirect in YuniKorn 1.10
	Route{
		Name:        RouteNameScheduler,
		Method:      "GET",
		Pattern:     "/ws/v1/fullstatedump",
		HandlerFunc: redirectDebug,
	},
}
