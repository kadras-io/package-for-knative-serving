# Knative Serving

<a href="https://slsa.dev/spec/v0.1/levels"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="The SLSA Level 3 badge"></a>

This project provides a [Carvel package](https://carvel.dev/kapp-controller/docs/latest/packaging) for [Knative Serving](https://knative.dev/docs/serving), a solution built on Kubernetes to support deploying and serving of applications and functions as serverless containers.

## Prerequisites

* Kubernetes 1.24+
* Carvel [`kctrl`](https://carvel.dev/kapp-controller/docs/latest/install/#installing-kapp-controller-cli-kctrl) CLI.
* Carvel [kapp-controller](https://carvel.dev/kapp-controller) deployed in your Kubernetes cluster. You can install it with Carvel [`kapp`](https://carvel.dev/kapp/docs/latest/install) (recommended choice) or `kubectl`.

  ```shell
  kapp deploy -a kapp-controller -y \
    -f https://github.com/vmware-tanzu/carvel-kapp-controller/releases/latest/download/release.yml
  ```

## Dependencies

Knative Serving requires the Contour package to be already installed in your Kubernetes cluster. You can install it
from the [Kadras package repository](https://github.com/arktonix/kadras-packages).

## Installation

First, add the [Kadras package repository](https://github.com/arktonix/kadras-packages) to your Kubernetes cluster.

  ```shell
  kubectl create namespace kadras-packages
  kctrl package repository add -r kadras-repo \
    --url ghcr.io/arktonix/kadras-packages \
    -n kadras-packages
  ```

Then, install the Knative Serving package.

  ```shell
  kctrl package install -i knative-serving \
    -p knative-serving.packages.kadras.io \
    -v 1.8.0+kadras.3 \
    -n kadras-packages
  ```

### Verification

You can verify the list of installed Carvel packages and their status.

  ```shell
  kctrl package installed list -n kadras-packages
  ```

### Version

You can get the list of Knative Serving versions available in the Kadras package repository.

  ```shell
  kctrl package available list -p knative-serving.packages.kadras.io -n kadras-packages
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
    -v 1.8.0+kadras.3 \
    -n kadras-packages \
    --values-file values.yml
  ```

## Upgrading

You can upgrade an existing package to a newer version using `kctrl`.

  ```shell
  kctrl package installed update -i knative-serving \
    -v <new-version> \
    -n kadras-packages
  ```

You can also update an existing package with a newer `values.yml` file.

  ```shell
  kctrl package installed update -i knative-serving \
    -n kadras-packages \
    --values-file values.yml
  ```

## Other

The recommended way of installing the Knative Serving package is via the [Kadras package repository](https://github.com/arktonix/kadras-packages). If you prefer not using the repository, you can install the package by creating the necessary Carvel `PackageMetadata` and `Package` resources directly using [`kapp`](https://carvel.dev/kapp/docs/latest/install) or `kubectl`.

  ```shell
  kubectl create namespace kadras-packages
  kapp deploy -a knative-serving-package -n kadras-packages -y \
    -f https://github.com/arktonix/package-for-knative-serving/releases/latest/download/metadata.yml \
    -f https://github.com/arktonix/package-for-knative-serving/releases/latest/download/package.yml
  ```

## Support and Documentation

For support and documentation specific to Knative Serving, check out [knative.dev](https://knative.dev).

## References

This package is based on the original Knative Serving package used in [Tanzu Community Edition](https://github.com/vmware-tanzu/community-edition) before its retirement.

## Supply Chain Security

This project is compliant with level 3 of the [SLSA Framework](https://slsa.dev).

<img src="https://slsa.dev/images/SLSA-Badge-full-level3.svg" alt="The SLSA Level 3 badge" width=200>
