load("@ytt:data", "data")
load("@ytt:struct", "struct")
load("@ytt:yaml", "yaml")

# Computes the data of the Knative Serving ConfigMaps from the package configuration.
# Each function returns the keys derived from the high-level settings for one ConfigMap.
# To support a new setting, add the keys it controls to the function for that ConfigMap.

def _domain():
  return {data.values.ingress.domain: ""}
end

# The Gateways of the Kadras Envoy Gateway package, where each Gateway has its own Envoy Service named `envoy-<gateway>`.
# Knative uses the Service to probe the routes.
def _gateway_entry(gateway):
  return [{
    "class": "envoy",
    "gateway": gateway.namespace + "/" + gateway.name,
    "service": gateway.namespace + "/envoy-" + gateway.name,
    "supported-features": ["HTTPRouteRequestTimeout"],
  }]
end

def _gateway():
  gateways = data.values.ingress.gateways
  return {"external-gateways": _gateway_entry(gateways.external), "local-gateways": _gateway_entry(gateways.internal)}
end

def _logging():
  result = {}
  for component in ["activator", "autoscaler", "controller", "net-gateway-api-controller", "queueproxy", "webhook"]:
    result["loglevel." + component] = data.values.observability.logging.level
  end
  return result
end

# TLS is terminated on the Gateway, so Knative doesn't request certificates. With HTTPS, the Gateway redirects
# the HTTP requests, including the ones Knative sends to probe the routes: Knative then assumes they're ready.
def _network():
  https = data.values.ingress.https
  return {
    "ingress-class": "gateway-api.ingress.networking.knative.dev",
    "external-domain-tls": "Disabled",
    "http-protocol": "Redirected" if https else "Enabled",
    "default-external-scheme": "https" if https else "http",
  }
end

# Maps the exporter of a signal to the Knative protocol: "none", "prometheus", "stdout", or the OTLP protocol.
def _protocol(signal):
  if not signal.enabled:
    return "none"
  elif signal.exporter == "otlp":
    return signal.protocol
  elif signal.exporter == "console":
    return "stdout"
  end
  return signal.exporter
end

def _observability():
  observability = data.values.observability
  result = {
    "logging.enable-request-log": observability.logging.request_logs,
    "metrics-export-interval": observability.metrics.export_interval,
    "request-metrics-export-interval": observability.request_metrics.export_interval,
    "tracing-sampling-rate": observability.tracing.sampling_rate,
  }
  for prefix, signal in [("metrics", observability.metrics), ("request-metrics", observability.request_metrics), ("tracing", observability.tracing)]:
    result[prefix + "-protocol"] = _protocol(signal)
    # Knative rejects an endpoint when the signal isn't exported via OTLP.
    if signal.enabled and signal.exporter == "otlp":
      result[prefix + "-endpoint"] = signal.endpoint
    end
  end
  return result
end

_computed = {
  "domain": _domain,
  "gateway": _gateway,
  "logging": _logging,
  "network": _network,
  "observability": _observability,
}

def _to_string(value):
  if type(value) == "string":
    return value
  elif type(value) == "bool":
    return "true" if value else "false"
  elif type(value) in ["dict", "list"]:
    return yaml.encode(value)
  end
  return str(value)
end

# Returns the names of the configurable ConfigMaps, without the "config-" prefix.
def configmap_names():
  return struct.decode(data.values.config).keys()
end

# Returns the data for the "config-<name>" ConfigMap: the keys computed from
# the package settings, overridden by the ones set in "config.<name>".
def configmap_data(name):
  result = _computed[name]() if name in _computed else {}
  result.update(struct.decode(data.values.config[name]))
  return {key: _to_string(value) for key, value in result.items()}
end
