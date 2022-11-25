# Knative Serving

This project provides a [Carvel package](https://carvel.dev/kapp-controller/docs/latest/packaging) for [Knative Serving](https://knative.dev/docs/serving), a solution built on Kubernetes to support deploying and serving of applications and functions as serverless containers.

## Components

* Knative Serving

## Prerequisites

* Install the [`kctrl`](https://carvel.dev/kapp-controller/docs/latest/install/#installing-kapp-controller-cli-kctrl) CLI to manage Carvel packages in a convenient way.
* Ensure [kapp-controller](https://carvel.dev/kapp-controller) is deployed in your Kubernetes cluster. You can do that with Carvel
[`kapp`](https://carvel.dev/kapp/docs/latest/install) (recommended choice) or `kubectl`.

```shell
kapp deploy -a kapp-controller -y \
  -f https://github.com/vmware-tanzu/carvel-kapp-controller/releases/latest/download/release.yml
```

## Dependencies

Knative Serving requires the Contour package to be already installed in the cluster. You can install it
from the [Kadras package repository](https://github.com/arktonix/carvel-packages).

## Installation

You can install the Knative Serving package directly or rely on the [Kadras package repository](https://github.com/arktonix/carvel-packages)
(recommended choice).

Follow the [instructions](https://github.com/arktonix/carvel-packages) to add the Kadras package repository to your Kubernetes cluster.

If you don't want to use the Kadras package repository, you can create the necessary `PackageMetadata` and
`Package` resources for the Knative Serving package directly.

```shell
kubectl create namespace carvel-packages
kapp deploy -a knative-serving-package -n carvel-packages -y \
    -f https://github.com/arktonix/package-for-knative-serving/releases/latest/download/metadata.yml \
    -f https://github.com/arktonix/package-for-knative-serving/releases/latest/download/package.yml
```

Either way, you can then install the Knative Serving package using [`kctrl`](https://carvel.dev/kapp-controller/docs/latest/install/#installing-kapp-controller-cli-kctrl).

```shell
kctrl package install -i knative-serving \
    -p knative-serving.packages.kadras.io \
    -v 1.8.0+kadras.1 \
    -n carvel-packages
```

You can retrieve the list of available versions with the following command.

```shell
kctrl package available list -p knative-serving.packages.kadras.io
```

You can check the list of installed packages and their status as follows.

```shell
kctrl package installed list -n carvel-packages
```

## Configuration

The Knative Serving package has the following configurable properties.

| Config | Default | Description |
|-------|-------------------|-------------|
| `namespace` | `knative-serving` | The namespace where to install Knative Serving. |
| `domain.type` | `nip.io` | Type of DNS resolution to use for the Knative services. If `real` DNS is chosen, you need to provide a `domain.name` or else use `sslip.io` or `nip.io`. |

You can define your configuration in a `values.yml` file.

```yaml
namespace: knative-serving

domain:
  type: nip.io
  name: ""
  url_template: "{{.Name}}.{{.Namespace}}.{{.Domain}}"

ingress:
  external:
    namespace: projectcontour
  internal:
    namespace: projectcontour

tls:
  certmanager:
    clusterissuer: ""

scaling:
  initial_scale: "1"
  min_scale: "0"
  max_scale: "0"
  allow_zero_initial_scale: "true"
  scale_down_delay: "0s"
```

Then, reference it from the `kctrl` command when installing or upgrading the package.

```shell
kctrl package install -i knative-serving \
    -p knative-serving.packages.kadras.io \
    -v 1.8.0+kadras.1 \
    -n carvel-packages \
    --values-file values.yml
```

## Documentation

For documentation specific to Knative Serving, check out [knative.dev](https://knative.dev).

## References

This package is based on the original Knative Serving package used in [Tanzu Community Edition](https://github.com/vmware-tanzu/community-edition) before its retirement.

## Supply Chain Security

This project is compliant with level 2 of the [SLSA Framework](https://slsa.dev).

<img src="https://slsa.dev/images/SLSA-Badge-full-level2.svg" alt="The SLSA Level 2 badge" width=200>
