/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package miniaggregator

import (
	"context"
	"net/http"
	"strings"

	"github.com/emicklei/go-restful/v3"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/endpoints/discovery"
	"k8s.io/apiserver/pkg/endpoints/handlers/negotiation"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	genericapiserver "k8s.io/apiserver/pkg/server"
)

func init() {
	// we need to add the options to empty v1
	// TODO fix the server code to avoid this
	metav1.AddToGroupVersion(DiscoveryScheme, schema.GroupVersion{Version: "v1"})
	// TODO: keep the generic API server from wanting this
	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	DiscoveryScheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)
}

var (
	// DiscoveryScheme defines methods for serializing and deserializing API objects.
	DiscoveryScheme = runtime.NewScheme()
	// DiscoveryCodecs provides methods for retrieving codecs and serializers for specific
	// versions and content types.
	DiscoveryCodecs = serializer.NewCodecFactory(DiscoveryScheme)
)

// Config represents the configuration needed to create an APIAggregator.
type Config struct {
	GenericConfig *genericapiserver.Config
}

// Complete fills in any fields not set that are required to have valid data and can be derived
// from other fields. If you're going to `ApplyOptions`, do that first. It's mutating the receiver.
func (c *Config) Complete() CompletedConfig {
	c.GenericConfig.PostStartHooks = map[string]genericapiserver.PostStartHookConfigEntry{}
	return CompletedConfig{
		completedConfig: &completedConfig{
			GenericConfig: c.GenericConfig.Complete(nil),
		},
	}
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
}

// CompletedConfig same as Config, just to swap private object.
type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

type runnable interface {
	RunWithContext(ctx context.Context) error
}

// preparedMiniAPIAggregator is a private wrapper that enforces a call of PrepareRun() before Run can be invoked.
type preparedMiniAPIAggregator struct {
	*MiniAPIAggregator
	runnable
}

func (s *MiniAPIAggregator) PrepareRun() (preparedMiniAPIAggregator, error) {
	prepared := s.GenericAPIServer.PrepareRun()

	return preparedMiniAPIAggregator{MiniAPIAggregator: s, runnablex: prepared}, nil

}

type MiniAPIAggregator struct {
	GenericAPIServer *genericapiserver.GenericAPIServer

	staticAPIPaths []metav1.APIGroup

	discoveryGroupLister discovery.GroupLister
}

func (c completedConfig) NewWithDelegate(
	delegationTarget genericapiserver.DelegationTarget,
	groupLister discovery.GroupLister,
) (*MiniAPIAggregator, error) {
	genericServer, err := c.GenericConfig.New("mini-aggregator", delegationTarget)
	if err != nil {
		return nil, err
	}

	s := &MiniAPIAggregator{
		discoveryGroupLister: groupLister,
		GenericAPIServer:     genericServer,
		staticAPIPaths:       apiStaticPaths(delegationTarget),
	}

	// Have to do this as a filter because of how the APIServerHandler.Director serves requests.
	s.GenericAPIServer.Handler.GoRestfulContainer.Filter(s.filterAPIsRequest)

	return s, nil
}

func apiStaticPaths(delegateAPIServer genericapiserver.DelegationTarget) []metav1.APIGroup {
	apiGroups := []metav1.APIGroup{}

	for _, curr := range delegateAPIServer.ListedPaths() {
		if curr == "/api/v1" {
			apiGroup := makeAPIGroup(schema.GroupVersion{Group: "", Version: "v1"})
			apiGroups = append(apiGroups, *apiGroup)
			continue
		}

		if !strings.HasPrefix(curr, "/apis/") {
			continue
		}
		// this comes back in a list that looks like /apis/rbac.authorization.k8s.io/v1alpha1
		tokens := strings.Split(curr, "/")
		if len(tokens) != 4 {
			continue
		}

		apiGroup := makeAPIGroup(schema.GroupVersion{Group: tokens[2], Version: tokens[3]})
		if apiGroup == nil {
			continue
		}
		apiGroups = append(apiGroups, *apiGroup)
	}

	return apiGroups
}

func makeAPIGroup(gv schema.GroupVersion) *metav1.APIGroup {
	return &metav1.APIGroup{
		Name: gv.Group,
		Versions: []metav1.GroupVersionForDiscovery{
			{
				GroupVersion: gv.String(),
				Version:      gv.Version,
			},
		},
	}
}

// filterAPIsRequest checks if the request is for /apis, and if so, it aggregates group discovery
// for the generic control plane server, apiextensions server (which provides the apiextensions.k8s.io group),
// and the CRDs themselves.
func (s *MiniAPIAggregator) filterAPIsRequest(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	if req.Request.URL.Path != "/apis" && req.Request.URL.Path != "/apis/" {
		chain.ProcessFilter(req, resp)
		return
	}
	length := len(s.staticAPIPaths)

	var groups []metav1.APIGroup
	if s.discoveryGroupLister != nil {
		var err error
		groups, err = s.discoveryGroupLister.Groups(req.Request.Context(), req.Request)
		if err != nil {
			responsewriters.InternalError(resp.ResponseWriter, req.Request, err)
			return
		}
		length += len(groups)
	}

	// Combine the slices using copy - more efficient than append
	combined := make([]metav1.APIGroup, length)

	var i int
	i += copy(combined[i:], s.staticAPIPaths)
	if s.discoveryGroupLister != nil {
		i += copy(combined[i:], groups)
	}
	responsewriters.WriteObjectNegotiated(DiscoveryCodecs, negotiation.DefaultEndpointRestrictions, schema.GroupVersion{}, resp.ResponseWriter, req.Request, http.StatusOK, &metav1.APIGroupList{Groups: combined}, false)
}
