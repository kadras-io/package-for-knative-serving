load("@ytt:regexp", "regexp")

# Validation helpers used by the values schema.
# They must not depend on data values, since they run while the schema is evaluated.

_dns_label = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"

def is_dns_label(value):
  return len(value) <= 63 and regexp.match("^" + _dns_label + "$", value)
end

def is_dns_name(value):
  return regexp.match("^" + _dns_label + "(\\." + _dns_label + ")*$", value)
end

# Whether the given observability signal (metrics, request metrics, or traces) is exported via OTLP.
def is_otlp_enabled(signal):
  return signal["enabled"] and signal["exporter"] == "otlp"
end
