# Knative Serving

![Test Workflow](https://github.com/kadras-io/package-for-knative-serving/actions/workflows/test.yml/badge.svg)
![Release Workflow](https://github.com/kadras-io/package-for-knative-serving/actions/workflows/release.yml/badge.svg)
[![The SLSA Level 3 badge](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/spec/v1.0/levels)
[![The Apache 2.0 license badge](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Follow us on Bluesky](https://img.shields.io/static/v1?label=Bluesky&message=Follow&color=1DA1F2)](https://bsky.app/profile/kadras.bsky.social)

A Carvel package for [Knative Serving](https://knative.dev/docs/serving), a solution built on Kubernetes to support deploying and serving of applications and functions as serverless containers.

## 🚀&nbsp; Getting Started

### Prerequisites

* Kubernetes 1.33+
* Carvel [`kctrl`](https://carvel.dev/kapp-controller/docs/latest/install/#installing-kapp-controller-cli-kctrl) CLI.
* Carvel [kapp-controller](https://carvel.dev/kapp-controller) deployed in your Kubernetes cluster. You can install it with Carvel [`kapp`](https://carvel.dev/kapp/docs/latest/install) (recommended choice) or `kubectl`.

  ```shell
  kapp deploy -a kapp-controller -y \
    -f https://github.com/carvel-dev/kapp-controller/releases/latest/download/release.yml
  ```

### Dependencies

Knative Serving requires [cert-manager](https://github.com/kadras-io/package-for-cert-manager) and the [Contour](https://github.com/kadras-io/package-for-contour) ingress controller. You can install them from the [Kadras package repository](https://github.com/kadras-io/kadras-packages).

### Installation

Add the Kadras [package repository](https://github.com/kadras-io/kadras-packages) to your Kubernetes cluster:

  ```shell
  kctrl package repository add -r kadras-packages \
    --url ghcr.io/kadras-io/kadras-packages \
    -n kadras-system --create-namespace
  ```

<details><summary>Installation without package repository</summary>
The recommended way of installing the Knative Serving package is via the Kadras <a href="https://github.com/kadras-io/kadras-packages">package repository</a>. If you prefer not using the repository, you can add the package definition directly using <a href="https://carvel.dev/kapp/docs/latest/install"><code>kapp</code></a> or <code>kubectl</code>.

  ```shell
  kubectl create namespace kadras-system
  kapp deploy -a knative-serving-package -n kadras-system -y \
    -f https://github.com/kadras-io/package-for-knative-serving/releases/latest/download/metadata.yml \
    -f https://github.com/kadras-io/package-for-knative-serving/releases/latest/download/package.yml
  ```
</details>

Install the Knative Serving package:

  ```shell
  kctrl package install -i knative-serving \
    -p knative-serving.packages.kadras.io \
    -v ${VERSION} \
    -n kadras-system
  ```

> **Note**
> You can find the `${VERSION}` value by retrieving the list of package versions available in the Kadras package repository installed on your cluster.
> 
>   ```shell
>   kctrl package available list -p knative-serving.packages.kadras.io -n kadras-system
>   ```

Verify the installed packages and their status:

  ```shell
  kctrl package installed list -n kadras-system
  ```

## 📙&nbsp; Documentation

Documentation, tutorials and examples for this package are available in the [docs](docs) folder.
For documentation specific to Knative Serving, check out [knative.dev](https://knative.dev/docs/serving).

## 🎯&nbsp; Configuration

The Knative Serving package can be customized via a `values.yml` file.

  ```yaml
  domain_name: labs.thomasvitale.com
  ingress_issuer: letsencrypt-issuer
  ```

Reference the `values.yml` file from the `kctrl` command when installing or upgrading the package.

  ```shell
  kctrl package install -i knative-serving \
    -p knative-serving.packages.kadras.io \
    -v ${VERSION} \
    -n kadras-system \
    --values-file values.yml
  ```

### Values

The Knative Serving package has the following configurable properties.

<details><summary>Configurable properties</summary>

| Config | Default | Description |
|-------|-------------------|-------------|
| `ca_cert_data` | `""` | PEM-encoded certificate data to trust TLS connections with a custom CA. |
| `policies.include` | `false` | Whether to include the out-of-the-box Kyverno policies to validate and secure the package installation. |
| `domain_name` | `""` | Domain name for Knative Services. It must be a valid DNS name. |
| `ingress_issuer` | `""` | A reference to the ClusterIssuer to use if you want to enable autoTLS. |
| `min_kubernetes_version` | `""` | The minimum Kubernetes version that this package will accept as valid. If not set, Knative Serving will accept the last 3 minor versions of Kubernetes. |

Settings for the Knative Serving workloads.

| Config | Default | Description |
|-------|-------------------|-------------|
| `workloads.activator.minReplicas` | `1` | The minimum number of replicas as controlled by a HorizontalPodAutoscaler. In order to enable high availability, it should be greater than 1. |
| `workloads.autoscaler.replicas` | `1` | The number of replicas for this Deployment. In order to enable high availability, it should be greater than 1. |
| `workloads.controller.replicas` | `1` | The number of replicas for this Deployment. In order to enable high availability, it should be greater than 1. |
| `workloads.domain_mapping.replicas` | `1` | The number of replicas for this Deployment. In order to enable high availability, it should be greater than 1. |
| `workloads.domain_mapping_webhook.replicas` | `1` | The number of replicas for this Deployment. In order to enable high availability, it should be greater than 1. |
| `workloads.webhook.minReplicas` | `1` | The minimum number of replicas as controlled by a HorizontalPodAutoscaler. In order to enable high availability, it should be greater than 1. |

Configuration stored in the `config-deployment` ConfigMap.

| Config | Default | Description |
|-------|-------------------|-------------|
| `config.deployment.progress-deadline` | `600s` | The duration to wait for the deployment to be ready before considering it failed. |
| `config.deployment.queue-sidecar-cpu-request` | `25m` | The queue proxy's CPU request. If omitted, a default value (currently '25m'), is used. |
| `config.deployment.queue-sidecar-cpu-limit` | `1000m` | The queue proxy's CPU limit. If omitted, a default value (currently `1000m`), is used when `queueproxy.resource-defaults` is set to `Enabled`. |
| `config.deployment.queue-sidecar-memory-request` | `50Mi` | The queue proxy's memory request. If omitted, a default value (currently `400Mi`), is used when `queueproxy.resource-defaults` is set to `Enabled`. |
| `config.deployment.queue-sidecar-memory-limit` | `200Mi` | The queue proxy's memory limit. If omitted, a default value (currently `800Mi`), is used when `queueproxy.resource-defaults` is set to `Enabled`. |

Configuration stored in the `config-network` ConfigMap.

| Config | Default | Description |
|-------|-------------------|-------------|
| `config.network.namespace-wildcard-cert-selector` | `""` | A LabelSelector which determines which namespaces should have a wildcard certificate provisioned. |
| `config.network.domain-template` | `{{.Name}}.{{.Namespace}}.{{.Domain}}` | The golang text template string to use when constructing the Knative Service's DNS name. |
| `config.network.http-protocol` | `Redirected` | Controls the behavior of the HTTP endpoint for the Knative ingress. `Enabled`: The Knative ingress will be able to serve HTTP connection. `Redirected`: The Knative ingress will send a 301 redirect for all http connections, asking the clients to use HTTPS. |
| `config.network.default-external-scheme` | `http` | Defines the scheme used for external URLs if autoTLS is not enabled. This can be used for making Knative report all URLs as `https`, for example, if you're fronting Knative with an external loadbalancer that deals with TLS termination and Knative doesn't know about that otherwise. |
| `config.network.rollout-duration` | `0` | The minimal duration in seconds over which the Configuration traffic targets are rolled out to the newest revision. |

Configuration stored in the `config-tracing` ConfigMap.

| Config | Default | Description |
|-------|-------------------|-------------|
| `config.tracing.backend` | `none` | The type of distributed tracing backend. Options: `none`, `zipkin`. |
| `config.tracing.zipkin-endpoint` | `http://tempo.observability-system.svc.cluster.local:9411/api/v2/spans` | The Zipkin collector endpoint where traces are sent. |
| `config.tracing.debug` | `false` | Enable the Zipkin debug mode. This allows all spans to be sent to the server bypassing sampling. |
| `config.tracing.sample-rate` | `0.1` | The percentage (0-1) of requests to trace. |

Settings for the Ingress controller.

| Config | Default | Description |
|-------|-------------------|-------------|
| `ingress.contour.default-tls-secret` | `""` | If auto-TLS is disabled, fallback to this certificate. An operator is required to setup a TLSCertificateDelegation for this Secret to be used. |
| `ingress.contour.external.namespace` | `projectcontour` | The namespace where the external Ingress controller is installed. |
| `ingress.contour.internal.namespace` | `projectcontour` | The namespace where the internal Ingress controller is installed. |

Settings for the corporate proxy.

| Config | Default | Description |
|-------|-------------------|-------------|
| `proxy.http_proxy` | `""` | The HTTP proxy to use for network traffic. |
| `proxy.https_proxy` | `""` | The HTTPS proxy to use for network traffic. |
| `proxy.no_proxy` | `""` | A comma-separated list of hostnames, IP addresses, or IP ranges in CIDR format that should not use a proxy. |

</details>

## 🛡️&nbsp; Security

The security process for reporting vulnerabilities is described in [SECURITY.md](SECURITY.md).

## 🖊️&nbsp; License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for more information.

## 🙏&nbsp; Acknowledgments

This package is inspired by the original Knative Serving package used in the [Tanzu Community Edition](https://github.com/vmware-tanzu/community-edition) project before its retirement.
