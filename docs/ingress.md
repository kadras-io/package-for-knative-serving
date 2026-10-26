# Networking and HTTPS

Knative Serving routes the traffic to Knative Services via the Kubernetes [Gateway API](https://gateway-api.sigs.k8s.io), using the [net-gateway-api](https://github.com/knative-extensions/net-gateway-api) networking layer. Knative creates `HTTPRoute` resources attached to the Gateways of the [Envoy Gateway](https://github.com/kadras-io/package-for-envoy-gateway) package, which must be installed in the cluster.

| Traffic | Gateway | URL |
|---------|---------|-----|
| From outside the cluster | `envoy-gateway-system/external` | `<name>.<namespace>.<domain>` |
| Within the cluster | `envoy-gateway-system/internal` | `<name>.<namespace>.svc.cluster.local` |

The cluster-local traffic doesn't go through the external Gateway, so it's not exposed outside the cluster.

If the Gateways of the Envoy Gateway package have different names or namespaces, configure them accordingly. Their routes must be allowed from any namespace.

```yaml
ingress:
  gateways:
    external:
      name: external
      namespace: envoy-gateway-system
    internal:
      name: internal
      namespace: envoy-gateway-system
```

## HTTPS

TLS is terminated on the external Gateway, which needs a certificate for the hostnames of the Knative Services. A wildcard certificate covers one level of subdomains, so each namespace with Knative Services needs its own: `*.<namespace>.<domain>`. Configure them in the Envoy Gateway package, which redirects HTTP requests to HTTPS. With Let's Encrypt, wildcard certificates require a DNS-01 challenge.

```yaml
# Envoy Gateway package
gateways:
  external:
    domain: example.com
    tls:
      issuer: letsencrypt-prod-issuer
      hostnames:
        - "*.team-a.example.com"
        - "*.team-b.example.com"
```

Then enable HTTPS in the Knative Serving package, so that Knative Services get `https` URLs.

```yaml
# Knative Serving package
ingress:
  domain: example.com
  https: true
```

## Limitations

The Gateway API networking layer is in beta. Compared with other networking layers, consider that:

* Knative checks that the routes are ready by sending requests to the external Gateway over HTTP. With HTTPS, they're redirected, and Knative assumes the routes are ready: a Knative Service can become ready a few seconds before it's actually reachable from outside the cluster;
* DomainMappings aren't supported, since Envoy Gateway doesn't route to the `ExternalName` Services they rely on (see [net-gateway-api#813](https://github.com/knative-extensions/net-gateway-api/issues/813));
* the encryption of the cluster-local and system-internal traffic isn't supported.

For more information, check the Knative Serving documentation about [installing a networking layer](https://knative.dev/docs/install/yaml-install/serving/install-serving-with-yaml/#install-a-networking-layer).
