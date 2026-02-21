# Configuring Observability

Monitor and observe the operation of Knative Serving using logs, metrics, and traces.

## Logs

For more information, check the [`config-observability`](https://github.com/knative/serving/blob/main/config/core/configmaps/observability.yaml) ConfigMap.

## Metrics

Prometheus and OpenTelemetry instrumentation is provided for Knative Serving. By default, the instrumentation is disabled. Via the `config.observability.*` properties, you can enable the generation of metrics and configure how they are exported to a metrics backend.

If you want to use Prometheus and enable the inclusion of Prometheus annotations for automatic scraping of Knative Serving metrics, you can set the `metrics-protocol` and `request-metrics-protocol` to `prometheus`:

```yaml
config:
  observability:
    metrics-protocol: "prometheus"
    request-metrics-protocol: "prometheus"
```

If you want to use OpenTelemetry and export metrics to an OpenTelemetry Collector, you can set the `metrics-protocol` and `request-metrics-protocol` to `http/protobuf` or `grpc` and configure the `metrics-endpoint` and `request-metrics-endpoint` properties to point to your OpenTelemetry Collector. Both HTTP/Protobuf and gRPC protocols are supported.

```yaml
config:
  observability:
    metrics-protocol: "http/protobuf"
    metrics-endpoint: "opentelemetry-collector.observability.svc.cluster.local:4318/v1/metrics"
    request-metrics-protocol: "http/protobuf"
    request-metrics-endpoint: "opentelemetry-collector.observability.svc.cluster.local:4318/v1/metrics"
    request-metrics-export-interval: 60s
```

For more information, check the Knative Serving documentation for [metrics](https://knative.dev/docs/serving/observability/metrics/collecting-metrics/) and the the [`config-observability`](https://github.com/knative/serving/blob/main/config/core/configmaps/observability.yaml) ConfigMap.

## Traces

OpenTelemetry instrumentation is provided for Knative Serving. By default, the instrumentation is disabled. Via the `config.observability.*` properties, you can enable the generation of traces and configure how they are exported to a distributed tracing backend.

Knative Serving supports exporting traces to an OpenTelemetry Collector using either the HTTP/Protobuf or gRPC protocol. To enable exporting traces to an OpenTelemetry Collector, you can set the `tracing-protocol` property to `http/protobuf` or `grpc` and configure the `tracing-endpoint` property to point to your OpenTelemetry Collector:

```yaml
config:
  observability:
    tracing-protocol: "http/protobuf"
    tracing-endpoint: "opentelemetry-collector.observability.svc.cluster.local:4318/v1/traces"
    tracing-sampling-rate: "1"
```

For more information, check the [`config-observability`](https://github.com/knative/serving/blob/main/config/core/configmaps/observability.yaml) ConfigMap.

## Dashboards

If you use the Grafana observability stack, you can refer to these [dashboards](https://github.com/knative-extensions/monitoring/tree/main/dashboards) as a foundation to build your own.
