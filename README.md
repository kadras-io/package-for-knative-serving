# Knative Serving

![Test Workflow](https://github.com/kadras-io/package-for-knative-serving/actions/workflows/test.yml/badge.svg)
![Release Workflow](https://github.com/kadras-io/package-for-knative-serving/actions/workflows/release.yml/badge.svg)
[![The SLSA Level 3 badge](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/spec/v1.0/levels)
[![The Apache 2.0 license badge](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Follow us on Bluesky](https://img.shields.io/static/v1?label=Bluesky&message=Follow&color=1DA1F2)](https://bsky.app/profile/kadras.bsky.social)

A Carvel package for [Knative Serving](https://knative.dev/docs/serving), a solution built on Kubernetes to support deploying and serving of applications and functions as serverless containers.

## ✨&nbsp; What's Included

* **Gateway API**. Knative Services exposed via the Gateways of the Kadras Envoy Gateway package, with the cluster-local traffic kept off the external Gateway.
* **HTTPS**. Knative Services served over HTTPS, with TLS terminated on the Gateway, and HTTP requests redirected to HTTPS.
* **High availability**. Configurable replicas, scaled by HorizontalPodAutoscalers or protected by PodDisruptionBudgets.
* **Observability**. Configurable logs, Prometheus or OpenTelemetry metrics, and OpenTelemetry traces.
* **Security**. The workloads comply with the `restricted` Pod Security Standard. Optional Kyverno policies verify the signatures and attestations of the Knative Serving images.

## 🚀&nbsp; Getting Started

### Prerequisites

* Kubernetes 1.35+
* Carvel [`kctrl`](https://carvel.dev/kapp-controller/docs/latest/install/#installing-kapp-controller-cli-kctrl) CLI.
* Carvel [kapp-controller](https://carvel.dev/kapp-controller) deployed in your Kubernetes cluster. You can install it with Carvel [`kapp`](https://carvel.dev/kapp/docs/latest/install) (recommended choice) or `kubectl`.

```shell
kapp deploy -a kapp-controller -y \
  -f https://github.com/carvel-dev/kapp-controller/releases/latest/download/release.yml
```

### Dependencies

Knative Serving requires [Envoy Gateway](https://github.com/kadras-io/package-for-envoy-gateway), which provides the Gateways routing the traffic to Knative Services. Some features rely on other packages:

* [cert-manager](https://github.com/kadras-io/package-for-cert-manager), to issue the certificates of the Envoy Gateway package for serving Knative Services over HTTPS.
* [Metrics Server](https://github.com/kadras-io/package-for-metrics-server), to scale the activator and webhook with HorizontalPodAutoscalers.
* [secretgen-controller](https://github.com/kadras-io/package-for-secretgen-controller), to authenticate with private registries.
* [Kyverno](https://github.com/kadras-io/package-for-kyverno), to enforce the image verification policies.

You can install them from the [Kadras package repository](https://github.com/kadras-io/kadras-packages).

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

Features:

* [Domain name](docs/domain.md)
* [Networking and HTTPS](docs/ingress.md)
* [High availability](docs/high-availability.md)
* [Observability](docs/observability.md)
* [Security](docs/security.md)

Operations:

* [Configuration and ytt overlays](docs/configuration.md)
* [Corporate proxy](docs/corporate-proxy.md)
* [Custom certificate authority](docs/custom-ca.md)
* [Verifying the release](docs/verify-release.md)

## 🎯&nbsp; Configuration

The Knative Serving package can be customized via a `values.yml` file.

```yaml
ingress:
  domain: labs.thomasvitale.com
  https: true
```

Reference the `values.yml` file from the `kctrl` command when installing or upgrading the package.

```shell
kctrl package install -i knative-serving \
  -p knative-serving.packages.kadras.io \
  -v ${VERSION} \
  -n kadras-system \
  --values-file values.yml
```

The configuration is organized in three layers:

1. Features. Typed settings for the main capabilities, listed under "Features" in the documentation above.
2. Knative ConfigMaps. Any key of the Knative Serving ConfigMaps via `config.<name>`, overriding the keys computed from the features. See [Configuration](docs/configuration.md).
3. Custom overlays. Anything else via your own ytt overlays. See [Configuration](docs/configuration.md#custom-overlays).

### Values

The Knative Serving package has the following configurable properties. The table is generated from the values schema with `task docs:values`.

<details><summary>Configurable properties</summary>

<!-- values-table:start -->

| Config | Default | Description |
|--------|---------|-------------|
| `ingress.domain` | `""` | The default domain name for all Knative Services, which are served as `<name>.<namespace>.<domain>`. Stored in the `config-domain` ConfigMap. Additional domains with label selectors can be configured via `config.domain`. |
| `ingress.https` | `false` | Whether the external Gateway serves the Knative Services over HTTPS, and redirects HTTP requests to HTTPS. Knative Services then get `https` URLs. TLS is terminated on the Gateway, which needs a certificate for each namespace with Knative Services (`*.<namespace>.<domain>`). |
| `ingress.gateways.external.name` | `"external"` | The name of the Gateway. |
| `ingress.gateways.external.namespace` | `"envoy-gateway-system"` | The namespace of the Gateway. |
| `ingress.gateways.internal.name` | `"internal"` | The name of the Gateway. |
| `ingress.gateways.internal.namespace` | `"envoy-gateway-system"` | The namespace of the Gateway. |
| `ca_cert_data` | `""` | PEM-encoded certificate data to trust TLS connections with a custom CA. |
| `workloads.activator.replicas` | `1` | The minimum number of replicas, as controlled by a HorizontalPodAutoscaler. |
| `workloads.autoscaler.replicas` | `1` | The number of replicas. Additional replicas are standby via leader election. With more than 1 replica, a PodDisruptionBudget is created. |
| `workloads.controller.replicas` | `1` | The number of replicas. Additional replicas are standby via leader election. With more than 1 replica, a PodDisruptionBudget is created. |
| `workloads.ingress_controller.replicas` | `1` | The number of replicas of the networking layer: `net-gateway-api-controller` and `net-gateway-api-webhook`. Additional controller replicas are standby via leader election. With more than 1 replica, PodDisruptionBudgets are created. |
| `workloads.webhook.replicas` | `1` | The minimum number of replicas, as controlled by a HorizontalPodAutoscaler. |
| `observability.logging.level` | `"info"` | The log level for all Knative Serving components. |
| `observability.logging.request_logs` | `false` | Whether the queue-proxy logs the requests received by Knative Services. |
| `observability.metrics.enabled` | `true` | Whether to produce metrics. |
| `observability.metrics.exporter` | `"prometheus"` | How the metrics are exported. With `prometheus`, the components expose them on port 9090, and their Pods are annotated for scraping. With `otlp`, they push them via OTLP to `endpoint`. |
| `observability.metrics.protocol` | `"grpc"` | The OTLP transport protocol, with the `otlp` exporter. |
| `observability.metrics.endpoint` | `""` | The OTLP endpoint metrics are exported to. Required with the `otlp` exporter. With `http/protobuf`, include the signal path. |
| `observability.metrics.export_interval` | `"60s"` | The metrics reporting period. |
| `observability.request_metrics.enabled` | `false` | Whether to produce request metrics. |
| `observability.request_metrics.exporter` | `"prometheus"` | How the request metrics are exported. With `prometheus`, the queue-proxy exposes them on port 9091. With `otlp`, it pushes them via OTLP to `endpoint`. |
| `observability.request_metrics.protocol` | `"grpc"` | The OTLP transport protocol, with the `otlp` exporter. |
| `observability.request_metrics.endpoint` | `""` | The OTLP endpoint request metrics are exported to. Required with the `otlp` exporter. With `http/protobuf`, include the signal path. |
| `observability.request_metrics.export_interval` | `"60s"` | The request metrics reporting period. |
| `observability.tracing.enabled` | `false` | Whether to produce traces. |
| `observability.tracing.exporter` | `"otlp"` | How the traces are exported. With `otlp`, they are pushed via OTLP to `endpoint`. With `console`, they are written to the standard output, for debugging. |
| `observability.tracing.protocol` | `"grpc"` | The OTLP transport protocol, with the `otlp` exporter. |
| `observability.tracing.endpoint` | `""` | The OTLP endpoint traces are exported to. Required with the `otlp` exporter. With `http/protobuf`, include the signal path. |
| `observability.tracing.sampling_rate` | `1` | The fraction of requests to trace, from 0 (never) to 1 (always). |
| `proxy.https_proxy` | `""` | The HTTPS proxy to use for network traffic. |
| `proxy.http_proxy` | `""` | The HTTP proxy to use for network traffic. |
| `proxy.no_proxy` | `""` | A comma-separated list of hostnames, IP addresses, or IP ranges in CIDR format that should not use a proxy. |
| `policies.enabled` | `false` | Whether to include Kyverno policies verifying the signatures of the Knative Serving images. Kyverno 1.19 or later must be installed in the cluster. |
| `config.autoscaler` | `{}` | Data for the `config-autoscaler` ConfigMap. |
| `config.certmanager` | `{}` | Data for the `config-certmanager` ConfigMap. |
| `config.defaults` | `{}` | Data for the `config-defaults` ConfigMap. |
| `config.deployment` | `{"queue-sidecar-cpu-request":"25m","queue-sidecar-cpu-limit":"1000m","queue-sidecar-memory-request":"50Mi","queue-sidecar-memory-limit":"200Mi"}` | Data for the `config-deployment` ConfigMap. |
| `config.domain` | `{}` | Data for the `config-domain` ConfigMap. |
| `config.features` | `{}` | Data for the `config-features` ConfigMap. |
| `config.gateway` | `{}` | Data for the `config-gateway` ConfigMap. |
| `config.gc` | `{}` | Data for the `config-gc` ConfigMap. |
| `config.leader-election` | `{}` | Data for the `config-leader-election` ConfigMap. |
| `config.logging` | `{}` | Data for the `config-logging` ConfigMap. |
| `config.network` | `{}` | Data for the `config-network` ConfigMap. |
| `config.observability` | `{}` | Data for the `config-observability` ConfigMap. |

<!-- values-table:end -->

</details>

## 🛠️&nbsp; Development

The development environment is defined with [devenv](https://devenv.sh). Enter it with `devenv shell`, or automatically with [direnv](https://direnv.net) after running `direnv allow`. Run `task --list` to see all the available tasks.

```shell
# Run the unit tests, which render the package and check the result without a cluster.
task test:config

# Create a local kind cluster and run the integration tests on it.
task cluster:setup
task test:integration

# Deploy the package from the local sources to the current cluster.
task dev

# Update the table of configurable values in this README after changing the values schema.
task docs:values
```

The unit tests are described in [test/unit/README.md](test/unit/README.md).

## 🛡️&nbsp; Security

The security process for reporting vulnerabilities is described in [SECURITY.md](SECURITY.md).

## 🖊️&nbsp; License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for more information.
