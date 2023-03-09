# Build package configuration
build: package
	cd package && kctrl package init

# Process the configuration manifests with ytt
ytt:
	ytt --file package/config

# Use ytt to generate an OpenAPI specification
schema:
	ytt -f package/config/values-schema.yml --data-values-schema-inspect -o openapi-v3 > schema-openapi.yml

# Check the ytt-annotated Kubernetes configuration and its validation
test-config:
	ytt -f package/config | kubeconform -ignore-missing-schemas -summary

# Run package tests
test-integration: test/test.sh
	chmod +x test/test.sh
	./test/test.sh
