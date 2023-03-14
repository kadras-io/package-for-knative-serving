# Configuring auto-TLS with cert-manager

Auto-TLS in Knative Serving can be enabled by providing the name of a cert-manager `ClusterIssuer`. If you installed [cert-manager](https://github.com/kadras-io/package-for-cert-manager) from the Kadras project, you can use the `kadras-ca-issuer` installed by the package via a self-signed certificate. Otherwise, you can reference the name of a `ClusterIssuer` created before installing the Knative Serving package.

```yaml
tls:
  certmanager:
    clusterissuer: kadras-ca-issuer
```

Optionally, you can also enable automatic redirect from HTTP to HTTPS.

```yaml
config:
  network:
    http-protocol: "Redirected"
```

For more information, check the Knative Serving documentation for [configuring HTTPS connections](https://knative.dev/docs/serving/using-a-tls-cert/) and [enabling auto-TLS certificates](https://knative.dev/docs/serving/using-auto-tls/).
