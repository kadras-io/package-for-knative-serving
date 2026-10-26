# Configuring High Availability

By default, one replica of each Knative Serving component is deployed. Configure the number of replicas to enable high availability.

```yaml
workloads:
  activator:
    replicas: 3
  autoscaler:
    replicas: 2
  controller:
    replicas: 2
  ingress_controller:
    replicas: 2
  webhook:
    replicas: 2
```

## Control plane

The `autoscaler`, `controller`, and `ingress_controller` components use leader election. Additional replicas take over when the leader becomes unavailable, and work is distributed among replicas based on buckets. The leader election can be tuned via `config.leader-election`. With more than 1 replica, a `PodDisruptionBudget` keeps at least one of them running during node maintenance.

The `ingress_controller` replicas apply to the [networking layer](ingress.md): `net-gateway-api-controller` and `net-gateway-api-webhook`.

## Data plane

The `activator` and `webhook` components are scaled by a `HorizontalPodAutoscaler`, which requires [Metrics Server](https://github.com/kadras-io/package-for-metrics-server) to be installed in your Kubernetes cluster. The number of replicas configures the minimum ensured by the `HorizontalPodAutoscaler`. The maximum is raised accordingly if needed.

With more than 1 replica, a `PodDisruptionBudget` prevents downtime during node maintenance. With 1 replica, it is removed so that it doesn't block draining nodes.

For more information, check the Knative Serving documentation for [configuring high availability components](https://knative.dev/docs/serving/config-ha).
