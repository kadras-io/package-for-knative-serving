# Configuring the domain name

Knative Services are exposed on a URL built from their name, namespace, and a domain name. Configure the default domain name for all Knative Services. It's required, and stored in the `config-domain` ConfigMap.

```yaml
ingress:
  domain: kadras.io
```

In scenarios where you don't have a domain name to use (for example, on a local environment), you can rely on the `sslip.io` domain which redirects to the specified IP address.

```yaml
ingress:
  domain: 127.0.0.1.sslip.io
```

## Additional domains

You can assign different domains to specific Knative Services based on their labels via the `config-domain` ConfigMap. The default domain is used for the Knative Services not matching any selector.

```yaml
config:
  domain:
    example.org:
      selector:
        app: nonprofit
```

## URL template

The template for the hostname of Knative Services is configured via the `config-network` ConfigMap.

```yaml
config:
  network:
    domain-template: "{{.Name}}-{{.Namespace}}.{{.Domain}}"
```

For more information, check the Knative Serving documentation on [configuring the default domain](https://knative.dev/docs/serving/using-a-custom-domain).
