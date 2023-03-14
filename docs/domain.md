# Configuring a domain name

A default domain name can be configured for all Knative Services. It's required if you want to enable auto-TLS.

```yaml
config:
  domain:
    name: "kadras.io"
```

In scenarios where you don't have a domain name to use (for example, on a local environment), you can rely on the `sslip.io` domain which redirects to the specified IP address.

```yaml
config:
  domain:
    name: "127.0.0.1.sslip.io"
```

For more information, check the Knative Serving documentation on [configuring domain names](https://knative.dev/docs/serving/using-a-custom-domain).
