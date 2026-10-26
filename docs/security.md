# Security

## Pod Security Standards

The Knative Serving workloads comply with the `restricted` [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/), which is enforced on the `knative-serving` namespace. The queue-proxy sidecars run in the namespaces of the Knative Services, so they're not affected.

## Kyverno policies

The package can include [Kyverno](https://github.com/kadras-io/package-for-kyverno) policies to verify the signatures of the Knative Serving images, signed keyless by the [Knative release identity](https://knative.dev/docs/reference/security/verifying-images/). The package defines them as [ImageValidatingPolicies](https://kyverno.io/docs/policy-types/image-validating-policy/) in the `knative-serving` namespace, so Kyverno 1.19 or later must be installed in the cluster.

```yaml
policies:
  enabled: true
```

The package includes two policies:

* `knative-serving-verify-image` verifies that the images are signed by the Knative release identity;
* `knative-serving-verify-provenance` verifies that the images have a [SLSA provenance](https://slsa.dev/provenance/v0.2) attestation signed by the Knative release identity, stating that they were built by the Knative release infrastructure (`https://prow.knative.dev`) from the Knative Serving or networking layer source repositories. See [verifying the SLSA provenance](https://knative.dev/docs/reference/security/verifying-images/#knative-slsa-provenance-signed).

The policies verify the images of the Knative Serving components and of both networking layers (`gcr.io/knative-releases/knative.dev/serving/*` and `gcr.io/knative-releases/knative.dev/net-*`) when their Pods are admitted. Consider that:

* only the Pods in the `knative-serving` namespace are verified, not the `queue-proxy` sidecar injected into the Pods of Knative Services in other namespaces;
* the signatures are verified against the Sigstore public infrastructure (Rekor and the TUF root), so Kyverno must be able to reach it. In a restricted network, configure the corporate proxy in the Kyverno package;
* images relocated to a different registry (for example, with `imgpkg copy`) don't match the policies anymore.

Check the [policies](../package/config/policies) folder to know what policies are included.
