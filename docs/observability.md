# Configuring Observability

Monitor and observe the operation of Knative Serving using logs, metrics, and traces.

## Logs

For more information, check the Knative Serving documentation for [logs](https://knative.dev/docs/serving/observability/logging/config-logging/).

## Metrics

Metrics configuration for all Knative Serving components is enabled by default using the Prometheus format. This package comes pre-configured with the necessary annotations to let Prometheus scrape metrics automatically from all Knative Serving components.

For more information, check the Knative Serving documentation for [metrics](https://knative.dev/docs/serving/observability/metrics/serving-metrics).

## Traces

OpenZipkin instrumentation is provided for Knative Serving. By default, the instrumentation is disabled. Via the `config.tracing.*` properties, you can enable the generation of traces and configure how they are exported to a distributed tracing backend.

Knative Serving supports exporting traces to Zipkin.

```yaml
tracing:
  backend: "zipkin"
  zipkin-endpoint: "http://tempo.observability-system.svc.cluster.local:9411/api/v2/spans"
  debug: "false"
  sample-rate: "0.1"
```

For more information, check the [`config-tracing`](https://github.com/knative/serving/blob/main/pkg/reconciler/revision/config/testdata/config-tracing.yaml) ConfigMap.

## Dashboards

If you use the Grafana observability stack, you can refer to these [dashboards](https://github.com/knative-sandbox/monitoring/tree/main/grafana) as a foundation to build your own.
