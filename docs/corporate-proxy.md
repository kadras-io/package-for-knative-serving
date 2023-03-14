# Using a corporate proxy

When running Knative Serving behind a corporate proxy, you can configure the controller to proxy the communication with the container registry when performing tag resolution.

```yaml
proxy:
  http_proxy: "proxy.kadras.io"
  https_proxy: "proxy.kadras.io"
  no_proxy: ""
```

For more information, check the Knative Serving documentation for [corporate proxy](https://knative.dev/docs/serving/tag-resolution/#corporate-proxy).
