# Knative Serving

![Test Workflow](https://github.com/kadras-io/package-for-knative-serving/actions/workflows/test.yml/badge.svg)
![Release Workflow](https://github.com/kadras-io/package-for-knative-serving/actions/workflows/release.yml/badge.svg)
[![The SLSA Level 3 badge](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/spec/v0.1/levels)
[![The Apache 2.0 license badge](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Follow us on Twitter](https://img.shields.io/static/v1?label=Twitter&message=Follow&color=1DA1F2)](https://twitter.com/kadrasIO)

A Carvel package for [Knative Serving](https://knative.dev/docs/serving), a solution built on Kubernetes to support deploying and serving of applications and functions as serverless containers.

## 🚀&nbsp; Getting Started

### Prerequisites

* Kubernetes 1.24+
* Carvel [`kctrl`](https://carvel.dev/kapp-controller/docs/latest/install/#installing-kapp-controller-cli-kctrl) CLI.
* Carvel [kapp-controller](https://carvel.dev/kapp-controller) deployed in your Kubernetes cluster. You can install it with Carvel [`kapp`](https://carvel.dev/kapp/docs/latest/install) (recommended choice) or `kubectl`.

  ```shell
  kapp deploy -a kapp-controller -y \
    -f https://github.com/carvel-dev/kapp-controller/releases/latest/download/release.yml
  ```

### Dependencies

Knative Serving requires the [Contour](https://github.com/kadras-io/package-for-contour) ingress controller. You can install it from the [Kadras package repository](https://github.com/kadras-io/kadras-packages).

### Installation

Add the Kadras [package repository](https://github.com/kadras-io/kadras-packages) to your Kubernetes cluster:

  ```shell
  kubectl create namespace kadras-packages
  kctrl package repository add -r kadras-packages \
    --url ghcr.io/kadras-io/kadras-packages \
    -n kadras-packages
  ```

<details><summary>Installation without package repository</summary>
The recommended way of installing the Knative Serving package is via the Kadras <a href="https://github.com/kadras-io/kadras-packages">package repository</a>. If you prefer not using the repository, you can add the package definition directly using <a href="https://carvel.dev/kapp/docs/latest/install"><code>kapp</code></a> or <code>kubectl</code>.

  ```shell
  kubectl create namespace kadras-packages
  kapp deploy -a knative-serving-package -n kadras-packages -y \
    -f https://github.com/kadras-io/package-for-knative-serving/releases/latest/download/metadata.yml \
    -f https://github.com/kadras-io/package-for-knative-serving/releases/latest/download/package.yml
  ```
</details>

Install the Knative Serving package:

  ```shell
  kctrl package install -i knative-serving \
    -p knative-serving.packages.kadras.io \
    -v ${VERSION} \
    -n kadras-packages
  ```

> **Note**
> You can find the `${VERSION}` value by retrieving the list of package versions available in the Kadras package repository installed on your cluster.
> 
>   ```shell
>   kctrl package available list -p knative-serving.packages.kadras.io -n kadras-packages
>   ```

Verify the installed packages and their status:

  ```shell
  kctrl package installed list -n kadras-packages
  ```

## 📙&nbsp; Documentation

Documentation, tutorials and examples for this package are available in the [docs](docs) folder.
For documentation specific to Knative Serving, check out [knative.dev](https://knative.dev/docs/serving).

## 🎯&nbsp; Configuration

The Knative Serving package can be customized via a `values.yml` file.

  ```yaml
  config:
    domain:
      name: kadras.io
  
  tls:
    certmanager:
      clusterissuer: lets-encrypt-issuer
  ```

Reference the `values.yml` file from the `kctrl` command when installing or upgrading the package.

  ```shell
  kctrl package install -i knative-serving \
    -p knative-serving.packages.kadras.io \
    -v ${VERSION} \
    -n kadras-packages \
    --values-file values.yml
  ```

### Values

The Knative Serving package has the following configurable properties.

<details><summary>Configurable properties</summary>

| Config | Default | Description |
|-------|-------------------|-------------|
| `namespace` | `knative-serving` | The namespace where to install Knative Serving. |
| `domain.name` | `127.0.0.1.sslip.io` | Your domain name. Either a real DNS name or else use `sslip.io` or `nip.io` for local installations. |
| `domain.template` | `{{.Name}}.{{.Namespace}}.{{.Domain}}` | The domain template to use when generating the DNS name for new services. |
| `ingress.external.namespace` | `projectcontour` | The namespace where the external Contour Ingress controller is installed. If you have only one, configure the same namespace for both external and internal. |
| `ingress.internal.namespace` | `projectcontour` | The namespace where the internal Contour Ingress controller is installed. If you have only one, configure the same namespace for both external and internal. |
| `tls.certmanager.clusterissuer` | `""` | Provide a Cert Manager `ClusterIssuer` if you want to enable auto-TLS. Optional. |
| `scaling.initial_scale` | `1` | The initial target scale of a revision after creation. |
| `scaling.min_scale` | `0` | The minimum scale of a revision. |
| `scaling.max_scale` | `0` | The maximum scale of a revision. If set to 0, the revision has no maximum scale. |
| `scaling.allow_zero_initial_scale` | `true` | Whether either the initial_scale config or the 'autoscaling.knative.dev/initial-scale' annotation can be set to 0. |
| `scaling.scale_down_delay` | `0s` | The amount of time that must pass at reduced concurrency before a scale down decision is applied. If 0s, no delay. |

</details>

## 🛡️&nbsp; Security

The security process for reporting vulnerabilities is described in [SECURITY.md](SECURITY.md).

## 🖊️&nbsp; License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for more information.
