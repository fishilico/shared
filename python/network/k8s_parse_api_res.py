#!/usr/bin/env python3
"""Parse the output of 'kubectl api-resources' to extract names of resource types

To get all Kubernetes resources of a cluster, the first step is to enumerate all available resource types.

Kubernetes' discovery API makes it available through 'kubectl api-resources'.
This results in a table looking like:

    NAME                                SHORTNAMES              APIVERSION                                  NAMESPACED   KIND
    bindings                                                    v1                                          true         Binding
    componentstatuses                   cs                      v1                                          false        ComponentStatus
    configmaps                          cm                      v1                                          true         ConfigMap
    endpoints                           ep                      v1                                          true         Endpoints
    events                              ev                      v1                                          true         Event
    limitranges                         limits                  v1                                          true         LimitRange
    namespaces                          ns                      v1                                          false        Namespace
    nodes                               no                      v1                                          false        Node
    persistentvolumeclaims              pvc                     v1                                          true         PersistentVolumeClaim
    persistentvolumes                   pv                      v1                                          false        PersistentVolume
    pods                                po                      v1                                          true         Pod
    podtemplates                                                v1                                          true         PodTemplate
    replicationcontrollers              rc                      v1                                          true         ReplicationController
    resourcequotas                      quota                   v1                                          true         ResourceQuota
    secrets                                                     v1                                          true         Secret
    serviceaccounts                     sa                      v1                                          true         ServiceAccount
    services                            svc                     v1                                          true         Service
    challenges                                                  acme.cert-manager.io/v1                     true         Challenge
    orders                                                      acme.cert-manager.io/v1                     true         Order

To list resources of a specific kind, the names and shortnames can be used.
Nevertheless there could be some ambiguous :

    NAME                                SHORTNAMES              APIVERSION                                  NAMESPACED   KIND
    certificates                        cert,certs              cert-manager.io/v1                          true         Certificate
    certificates                        kcert                   networking.internal.knative.dev/v1alpha1    true         Certificate

    events                              ev                      events.k8s.io/v1                            true         Event
    events                              ev                      v1                                          true         Event

    networkpolicies                                             crd.projectcalico.org/v1                    true         NetworkPolicy
    networkpolicies                     netpol                  networking.k8s.io/v1                        true         NetworkPolicy

    nodes                                                       metrics.k8s.io/v1beta1                      false        NodeMetrics
    nodes                               no                      v1                                          false        Node

    pods                                                        metrics.k8s.io/v1beta1                      true         PodMetrics
    pods                                po                      v1                                          true         Pod

    services                            kservice,ksvc           serving.knative.dev/v1                      true         Service
    services                            svc                     v1                                          true         Service

To resolve any ambiguity, the full name suffixed with the API Group name has to be used:

    kubectl get -n default pods.metrics.k8s.io

The full names can also be listed with option '-o name':

    kubectl api-resources -o name --namespaced=false
    kubectl api-resources -o name --namespaced=true

The table does not do this by default, because the API URL to access a resource use 'GROUP/VERSION'.
More precisely, they are (according to the documentation https://kubernetes.io/docs/reference/using-api/api-concepts/):

    /apis/GROUP/VERSION/RESOURCETYPE/NAME for cluster-scoped resources
    /apis/GROUP/VERSION/namespaces/NAMESPACE/RESOURCETYPE/NAME for namespace-scoped resources

This Python script reconstructs the full resource names from the output of 'kubectl api-resources'.

For information, raw HTTPS API calls look like:

    TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    curl -i https://kubernetes.default.svc/api \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Accept: application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList'

    HTTP/2 200
    audit-id: ...
    cache-control: public
    content-type: application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList
    etag: "..."
    vary: Accept
    x-kubernetes-pf-flowschema-uid: ...
    x-kubernetes-pf-prioritylevel-uid: ...
    date: ...

    {
      "kind": "APIGroupDiscoveryList",
      "apiVersion": "apidiscovery.k8s.io/v2",
      "metadata": {},
      "items": [
        {
          "metadata": {
            "creationTimestamp": null
          },
          "versions": [
            {
              "version": "v1",
              "resources": [
                {
                  "resource": "bindings",
                  "responseKind": {
                    "group": "",
                    "version": "",
                    "kind": "Binding"
                  },
                  "scope": "Namespaced",
                  "singularResource": "binding",
                  "verbs": [
                    "create"
                  ]
                },
    ...

The Accept request header and Content-Type reponse header indicate Group/Version/Kind in fields g/v/as.

Documentation: https://kubernetes.io/docs/reference/kubectl/generated/kubectl_api-resources/

Source code of 'kubectl api-resources':
- CLI: https://github.com/kubernetes/kubernetes/blob/v1.33.0/staging/src/k8s.io/kubectl/pkg/cmd/apiresources/apiresources.go
- Discovery Client: https://github.com/kubernetes/kubernetes/blob/v1.33.0/staging/src/k8s.io/client-go/discovery/discovery_client.go
- Server JSON files defining base Kubernetes resource types: https://github.com/kubernetes/kubernetes/tree/v1.33.0/api/discovery
"""
import argparse
import re
import sys

from pathlib import Path
from typing import TextIO


def parse_kubectl_api_resources(stream: TextIO) -> dict[str, bool]:
    name2namespaced: dict[str, bool] = {}

    # Positions of the columns
    col_positions: dict[int, str] = {}
    col_stops: list[int] = []

    for line in stream:
        line = line.strip()
        if not line or line.startswith("error: "):
            continue
        if line.startswith("E0116 ") and line.endswith(": the server is currently unable to handle the request"):
            # Ignore "E0116 13:37:42.123456     413 memcache.go:287] couldn't get resource list for metrics.k8s.io/v1beta1: the server is currently unable to handle the request"
            continue

        if not col_positions:
            # Parse the header
            if not line.startswith("NAME    "):
                raise RuntimeError(f"Unexpected header line {line!r}")
            col_names = line.split()
            if len(col_names) != len(set(col_names)):
                raise RuntimeError(f"Unexpected duplicate column name in header line {line!r}")
            col_positions = {(" " + line + " ").index(" " + col_name + " "): col_name for col_name in col_names}
            col_stops = sorted(col_positions.keys())
            col_stops.append(-1)
            continue

        values: dict[str, str] = {}
        for icol, col_pos in enumerate(col_stops[:-1]):
            next_pos = col_stops[icol + 1]
            col_value = line[col_pos:next_pos].rstrip()
            values[col_positions[col_pos]] = col_value

        name = values["NAME"]
        apiver = values["APIVERSION"]
        namespaced = {"true": True, "false": False}[values["NAMESPACED"]]

        if matches := re.match(r"^(.*)/(v[0-9]+(?:alpha|beta)?[0-9]*)$", apiver):
            # Match "cert-manager.io/v1" to extract the group and version
            name += "." + matches.group(1)
            apiver = matches.group(2)
        elif not re.match(r"^(v[0-9]+(?:alpha|beta)?[0-9]*)$", apiver):
            print(f"Warning: unexpected API version {apiver!r} in {values!r}", file=sys.stderr)

        if name not in name2namespaced:
            name2namespaced[name] = namespaced
        elif name2namespaced[name] != namespaced:
            raise ValueError(f"Duplicate name {name!r} in api-resources result")

    return name2namespaced


def main() -> None:
    parser = argparse.ArgumentParser(
        description="List names of resource types from the output of 'kubectl api-resources'"
    )
    parser.add_argument("files", nargs="+", type=Path, help="Output(s) of 'kubectl api-resources'")
    group_ns = parser.add_mutually_exclusive_group()
    group_ns.add_argument("-n", "--namespaced", action="store_true", help="dump only namespaced resources")
    group_ns.add_argument("-c", "--cluster-scoped", action="store_true", help="dump only cluster-scoped resources")
    args = parser.parse_args()

    assert not (args.namespaced and args.cluster_scoped)

    if args.files:
        name2namespaced: dict[str, bool] = {}
        for file_path in args.files:
            with file_path.open("r") as f:
                name2namespaced |= parse_kubectl_api_resources(f)
    else:
        # Use stdin
        name2namespaced = parse_kubectl_api_resources(sys.stdin)

    for name, namespaced in sorted(name2namespaced.items()):
        if args.namespaced:
            if namespaced:
                print(name)
        elif args.cluster_scoped:
            if not namespaced:
                print(name)
        else:
            print(name)


if __name__ == "__main__":
    main()
