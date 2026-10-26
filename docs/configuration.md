# Configuring Knative Serving

Besides the features configured via dedicated settings, you can customize Knative Serving via its ConfigMaps or via your own ytt overlays.

## ConfigMaps

Each Knative Serving ConfigMap can be configured via `config.<name>`, where `<name>` is the ConfigMap name without the `config-` prefix. The supported ConfigMaps are `autoscaler`, `certmanager`, `defaults`, `deployment`, `domain`, `features`, `gateway`, `gc`, `leader-election`, `logging`, `network`, and `observability`.

```yaml
config:
  autoscaler:
    max-scale: 10
    scale-to-zero-grace-period: 60s
  features:
    kubernetes.podspec-affinity: enabled
```

The data of each ConfigMap is composed as follows, where each step overrides the previous one:

1. the upstream defaults of Knative Serving;
2. the keys computed from the package settings, such as `ingress.https` or `observability.*`;
3. the keys configured via `config.<name>`.

Values don't need to be strings. Numbers and booleans are converted to strings, maps and lists are encoded as YAML.

The package is the source of truth for the ConfigMaps. Changes applied directly in the cluster are reverted at the next reconciliation, so make sure to configure them via the package instead.

For the available options, check the `_example` key in each ConfigMap or the Knative Serving documentation on [configuring Knative Serving](https://knative.dev/docs/serving/configuration/config-defaults/).

## Custom overlays

For customizations not covered by the package settings, you can provide your own [ytt overlays](https://carvel.dev/ytt/docs/latest/ytt-overlays/). Store them in a Secret and reference it from the `PackageInstall`. The overlays are applied after the ones included in the package.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: knative-serving-overlays
  namespace: kadras-system
stringData:
  controller-resources.yml: |
    #@ load("@ytt:overlay", "overlay")
    #@overlay/match by=overlay.subset({"kind": "Deployment", "metadata": {"name": "controller"}})
    ---
    spec:
      template:
        spec:
          containers:
            #@overlay/match by="name"
            - name: controller
              resources:
                limits:
                  memory: 2Gi
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageInstall
metadata:
  name: knative-serving
  namespace: kadras-system
  annotations:
    ext.packaging.carvel.dev/ytt-paths-from-secret-name.0: knative-serving-overlays
spec:
  # ...
```

For more information, check the kapp-controller documentation on [customizing a package installation](https://carvel.dev/kapp-controller/docs/latest/package-install-extensions/).
