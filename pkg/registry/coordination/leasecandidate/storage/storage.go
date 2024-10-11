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

package storage

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"

	"k8s.io/apiserver/pkg/registry/coordination/leasecandidate"
	coordinationapi "k8s.io/kubernetes/pkg/apis/coordination"
	"k8s.io/kubernetes/pkg/printers"
	printersinternal "k8s.io/kubernetes/pkg/printers/internalversion"
	printerstorage "k8s.io/kubernetes/pkg/printers/storage"
)

// REST implements a RESTStorage for leasecandidates against etcd
type REST struct {
	*genericregistry.Store
}

// NewREST returns a RESTStorage object that will work against leasecandidates.
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, error) {
	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &coordinationapi.LeaseCandidate{} },
		NewListFunc:               func() runtime.Object { return &coordinationapi.LeaseCandidateList{} },
		DefaultQualifiedResource:  coordinationapi.Resource("leasecandidates"),
		SingularQualifiedResource: coordinationapi.Resource("leasecandidate"),

		CreateStrategy: leasecandidate.Strategy,
		UpdateStrategy: leasecandidate.Strategy,
		DeleteStrategy: leasecandidate.Strategy,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: leasecandidate.GetAttrs}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, err
	}

	return &REST{store}, nil
}
