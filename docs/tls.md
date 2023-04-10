# Configuring auto-TLS with cert-manager

Auto-TLS in Knative Serving can be enabled by providing the name of a cert-manager `ClusterIssuer` that must be created in the cluster before installing the Knative Serving package.

```yaml
ingress_issuer: kadras-ca-issuer
```

Optionally, you can also enable automatic redirect from HTTP to HTTPS.

```yaml
config:
  network:
    http-protocol: "Redirected"
```

For more information, check the Knative Serving documentation for [configuring HTTPS connections](https://knative.dev/docs/serving/using-a-tls-cert/) and [enabling auto-TLS certificates](https://knative.dev/docs/serving/using-auto-tls/).
