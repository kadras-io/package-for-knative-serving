# Configuring Observability

Monitor and observe the operation of Knative Serving using logs, metrics, and traces. The configuration is stored in the `config-observability` and `config-logging` ConfigMaps.

## Logs

Configure the log level for all Knative Serving components, and whether the queue-proxy logs the requests received by Knative Services.

```yaml
observability:
  logging:
    level: debug
    request_logs: true
```

The format of the request logs and the log level of individual components can be customized via `config.observability` and `config.logging`. See [Configuration](configuration.md).

## Metrics

Metrics are configured separately for the control plane (`metrics`) and for the requests handled by the queue-proxy in the Pods of Knative Services (`request_metrics`). Each one is either exposed to Prometheus or pushed to an OpenTelemetry Collector via OTLP, following the [OpenTelemetry SDK](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/) conventions: an `exporter`, and a `protocol` for OTLP.

By default, the control plane metrics are exposed to Prometheus on port 9090, and the control plane Pods are annotated for automatic scraping. Request metrics are disabled. You can expose them to Prometheus on port 9091 of the queue-proxy.

```yaml
observability:
  request_metrics:
    enabled: true
```

To export metrics to an OpenTelemetry Collector, use the `otlp` exporter and configure the endpoint. The protocol is `grpc` by default. With `http/protobuf`, include the signal path in the endpoint.

```yaml
observability:
  metrics:
    exporter: otlp
    endpoint: http://opentelemetry-collector.observability.svc.cluster.local:4317
  request_metrics:
    enabled: true
    exporter: otlp
    protocol: http/protobuf
    endpoint: http://opentelemetry-collector.observability.svc.cluster.local:4318/v1/metrics
    export_interval: 30s
```

## Traces

Traces are disabled by default. To export them to an OpenTelemetry Collector, enable them and configure the endpoint. The sampling rate ranges from 0 (never sample) to 1 (always sample).

```yaml
observability:
  tracing:
    enabled: true
    endpoint: http://opentelemetry-collector.observability.svc.cluster.local:4317
    sampling_rate: 0.1
```

For debugging, the `console` exporter writes the traces to the standard output of the components.

```yaml
observability:
  tracing:
    enabled: true
    exporter: console
```

## Dashboards

If you use the Grafana observability stack, you can refer to these [dashboards](https://github.com/knative-extensions/monitoring/tree/main/dashboards) as a foundation to build your own.

For more information, check the Knative Serving documentation for [metrics](https://knative.dev/docs/serving/observability/metrics/collecting-metrics/) and the [`config-observability`](https://github.com/knative/serving/blob/main/config/core/configmaps/observability.yaml) ConfigMap.
