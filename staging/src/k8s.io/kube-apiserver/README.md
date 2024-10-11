# kube-apiserver

Library for building a Kubernetes API server.


## Purpose

This library contains code to create Kubernetes Generic control plane server complete with delegated authentication and authorization,
`kubectl` compatible discovery information, optional admission chain, and versioned types.

## Compatibility

There are *NO compatibility guarantees* for this repository, yet.  It is in direct support of Kubernetes, so branches
will track Kubernetes and be compatible with that repo.  As we more cleanly separate the layers, we will review the
compatibility guarantee. We have a goal to make this easier to use in the future.


## Where does it come from?

`generic-controlplane` is synced from https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/generic-controlplane.
Code changes are made in that location, merged into `k8s.io/kubernetes` and later synced here.


## Things you should *NOT* do

 1. Directly modify any files under `pkg` in this repo.  Those are driven from `k8s.io/kubernetes/staging/src/k8s.io/generic-controlplane`.
 2. Expect compatibility.  This repo is changing quickly in direct support of
    Kubernetes and the API isn't yet stable enough for API guarantees.

