#!/bin/bash

set -Eeuo pipefail

echo -e "\n🚢 Setting up Kubernetes cluster...\n"

kapp deploy -a test-setup -f test/test-setup -y
kubectl config set-context --current --namespace=carvel-test

# Wait for the generation of a token for the new Service Account
while [ $(kubectl get configmap kube-root-ca.crt --no-headers | wc -l) -eq 0 ] ; do
  sleep 3
done

echo -e "\n🔌 Installing test dependencies..."

kapp deploy -a kapp-controller -y \
  -f https://github.com/vmware-tanzu/carvel-kapp-controller/releases/latest/download/release.yml

kapp deploy -a kadras-repo -y \
  -f https://github.com/arktonix/kadras-packages/releases/latest/download/package-repository.yml

kapp deploy -a test-dependencies -f test/test-dependencies -y

echo -e "📦 Deploying and verifying Carvel package...\n"

cd package
kctrl dev -f package-resources.yml --local -y
cd ..

echo -e "🎮 Verifying package..."

status=$(kapp inspect -a knative-serving.app --status --json | jq '.Lines[1]' -)
if [[ '"Succeeded"' == ${status} ]]; then
    echo -e "✅ The package has been installed successfully.\n"
else
    echo -e "🚫 Something wrong happened during the installation of the package.\n"
    exit 1
fi

echo -e "🏎️ Deploying and verifying Knative Service..."

kapp deploy -a hello -f test/test-application -y
