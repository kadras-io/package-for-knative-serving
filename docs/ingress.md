# Configuring the Ingress controller

Knative Serving uses an Ingress controller to serve all incoming traffic. This package configures Knative Serving with Contour. Make sure you install the [Contour](https://github.com/kadras-io/package-for-contour) package before installing Knative Serving.

Two configurations are supported: one Contour instance used for both external and internal services, or two separate instances. Either way, you're required to specify the namespace where to find the Contour instance to use in each case.

```yaml
ingress:
  contour:
    external:
      namespace: projectcontour
    internal:
      namespace: projectcontour
```

For more information, check the Knative Serving documentation about [installing a networking layer](https://knative.dev/docs/install/yaml-install/serving/install-serving-with-yaml/#install-a-networking-layer).
