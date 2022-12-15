//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright The KCP Authors.

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

// Code generated by kcp code-generator. DO NOT EDIT.

package v1beta1

import (
	"context"

	kcpclient "github.com/kcp-dev/apimachinery/pkg/client"
	"github.com/kcp-dev/logicalcluster/v2"

	rbacv1beta1 "k8s.io/api/rbac/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	rbacv1beta1client "k8s.io/client-go/kubernetes/typed/rbac/v1beta1"
)

// ClusterRolesClusterGetter has a method to return a ClusterRoleClusterInterface.
// A group's cluster client should implement this interface.
type ClusterRolesClusterGetter interface {
	ClusterRoles() ClusterRoleClusterInterface
}

// ClusterRoleClusterInterface can operate on ClusterRoles across all clusters,
// or scope down to one cluster and return a rbacv1beta1client.ClusterRoleInterface.
type ClusterRoleClusterInterface interface {
	Cluster(logicalcluster.Name) rbacv1beta1client.ClusterRoleInterface
	List(ctx context.Context, opts metav1.ListOptions) (*rbacv1beta1.ClusterRoleList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

type clusterRolesClusterInterface struct {
	clientCache kcpclient.Cache[*rbacv1beta1client.RbacV1beta1Client]
}

// Cluster scopes the client down to a particular cluster.
func (c *clusterRolesClusterInterface) Cluster(name logicalcluster.Name) rbacv1beta1client.ClusterRoleInterface {
	if name == logicalcluster.Wildcard {
		panic("A specific cluster must be provided when scoping, not the wildcard.")
	}

	return c.clientCache.ClusterOrDie(name).ClusterRoles()
}

// List returns the entire collection of all ClusterRoles across all clusters.
func (c *clusterRolesClusterInterface) List(ctx context.Context, opts metav1.ListOptions) (*rbacv1beta1.ClusterRoleList, error) {
	return c.clientCache.ClusterOrDie(logicalcluster.Wildcard).ClusterRoles().List(ctx, opts)
}

// Watch begins to watch all ClusterRoles across all clusters.
func (c *clusterRolesClusterInterface) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.clientCache.ClusterOrDie(logicalcluster.Wildcard).ClusterRoles().Watch(ctx, opts)
}