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

	genericapiserver "k8s.io/apiserver/pkg/server"
	openapicommon "k8s.io/kube-openapi/pkg/common"
)

// Config represents the configuration needed to create an APIAggregator.
type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
}

// Complete fills in any fields not set that are required to have valid data and can be derived
// from other fields. If you're going to `ApplyOptions`, do that first. It's mutating the receiver.
func (c *Config) Complete() CompletedConfig {
	return CompletedConfig{
		completedConfig: &completedConfig{
			GenericConfig: c.GenericConfig.Complete(),
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
	runnable runnable
}

func (s *MiniAPIAggregator) PrepareRun() (preparedMiniAPIAggregator, error) {
	prepared := s.GenericAPIServer.PrepareRun()

	return preparedMiniAPIAggregator{MiniAPIAggregator: s, runnable: prepared}, nil

}

type MiniAPIAggregator struct {
	GenericAPIServer *genericapiserver.GenericAPIServer

	// Enable swagger and/or OpenAPI if these configs are non-nil.
	OpenAPIConfig *openapicommon.Config

	// Enable OpenAPI V3 if these configs are non-nil
	OpenAPIV3Config *openapicommon.OpenAPIV3Config
}

func (c completedConfig) NewWithDelegate(delegationTarget genericapiserver.DelegationTarget) (*MiniAPIAggregator, error) {
	genericServer, err := c.GenericConfig.New("mini-aggregator", delegationTarget)
	if err != nil {
		return nil, err
	}
	return &MiniAPIAggregator{
		GenericAPIServer: genericServer,
		OpenAPIConfig:    c.GenericConfig.OpenAPIConfig,
		OpenAPIV3Config:  c.GenericConfig.OpenAPIV3Config,
	}, nil
}
