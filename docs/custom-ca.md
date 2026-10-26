# Trusting a custom certificate authority

If you need to interact with a private registry using a certificate signed by a custom certificate authority, you can pass the PEM-encoded certificate of the authority when installing or upgrading the package. The controller trusts it, on top of the system certificate authorities, when resolving image tags to digests.

```yaml
ca_cert_data: |
  -----BEGIN CERTIFICATE-----
  MIICvjCCAaYCCQDhcJuwMw6yZzANBgkqhkiG9w0BAQsFADAhMQswCQYDVQQGEwJE
  ...
  -----END CERTIFICATE-----
```

The certificate is stored in the `knative-serving-ca-certificates` Secret and mounted in the controller at `/etc/ssl/certs-extra`.

For more information, check the Knative Serving documentation on [tag resolution](https://knative.dev/docs/serving/tag-resolution/).
