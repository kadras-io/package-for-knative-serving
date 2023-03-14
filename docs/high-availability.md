# Configuring High Availability

High availability for Knative Serving can be configured using different strategies for the control plane and the data plane.

## High availability for the control plane

The `autoscaler` and `controller` components support high availability following an active/active model based on the leader election strategy. Work is distributed among replicas based on buckets.

The leader election configuration is provided via the `config-leader-election` ConfigMap. By default, only one replica for each component is deployed, meaning high availability is disabled. To enable high availability, it's recommended to configure at least 3 replicas for each component.

```yaml
workloads:
  autoscaler:
    replicas: 3
  controller:
    replicas: 3
```

You can disable high availability for those components by scaling them down to 1 replica.

## High availability for the data plane

High availability for the `activator` and `webhook` components is controlled by a `HorizontalPodAutoscaler`, and requires [Metrics Server](https://github.com/kadras-io/package-for-metrics-server) to be installed in your Kubernetes cluster.

The following configuration enables the high availability by specifying a minimum number of replicas ensured by the `HorizontalPodAutoscaler`. When more than 1 replica is configured, a `PodDisruptionBudget` is automatically created to prevent downtime during node unavailability.

```yaml
workloads:
  activator:
    minReplicas: 3
  webhook:
    minReplicas: 2
```

For more information, check the Knative Serving documentation for [configuring high availability components](https://knative.dev/docs/serving/config-ha).
