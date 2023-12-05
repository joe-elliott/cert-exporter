#!/bin/bash

# requires a k8s cluster running with cert-manager running in it
# requires kind https://github.com/kubernetes-sigs/kind

set -o errexit

validateMetrics() {
    metrics=$1
    expectedVal=$2    

    raw=$(curl --silent http://localhost:8080/metrics | grep "$metrics" || true)

    if [ "$raw" == "" ]; then
      echo "TEST FAILURE: $metrics" 
      echo "  Unable to find metrics string"
      return 0
    fi

    if [ "$expectedVal" == "" ]; then 
      echo "TEST SUCCESS: $metrics found.  Not testing expected val."
      return 0
    fi

    val=${raw#* }
    valInDays=$(awk "BEGIN {printf \"%.0f\", $val / (24 * 60 * 60)}")

    if [ "$expectedVal" -ne "$valInDays" ]; then
      echo "TEST FAILURE: $metrics"
      echo "  Expected  : $expectedVal"
      echo "  Raw       : $raw"
      echo "  Val       : $val"
      echo "  ValInDays : $valInDays"
    else 
      echo "TEST SUCCESS: $metrics"
    fi
}

CERT_EXPORTER_PATH="../../dist/cert-exporter_$(go env GOOS)_$(go env GOARCH)_v1/cert-exporter"
KIND_CLUSTER_NAME=cert-exporter
CONFIG_PATH=cert-exporter.kubeconfig

echo -n "Create cluster"
kind create cluster --name=$KIND_CLUSTER_NAME --kubeconfig=$CONFIG_PATH

kubectl --kubeconfig=$CONFIG_PATH create namespace cert-manager
kubectl --kubeconfig=$CONFIG_PATH label namespace cert-manager certmanager.k8s.io/disable-validation=true
kubectl --kubeconfig=$CONFIG_PATH apply -f https://github.com/jetstack/cert-manager/releases/download/v1.8.1/cert-manager.yaml

kubectl --kubeconfig=$CONFIG_PATH wait --for=condition=available deploy --all -n cert-manager --timeout=3m
sleep 10 # NB give the deploy more time to be ready. let us know if you know a better way!

kubectl --kubeconfig=$CONFIG_PATH apply -f ./certs.yaml
sleep 10 # NB give cert-manager time to create the certificates. let us know if you know a better way to do this!

CERT_REQUEST=$(kubectl --kubeconfig=$CONFIG_PATH get certificaterequest -n cert-manager-test -l="testlabel=test" -o jsonpath={'.items[].metadata.name'})

echo "** Testing Label Selector"
# run exporter
$CERT_EXPORTER_PATH \
    --kubeconfig=$CONFIG_PATH \
    --secrets-annotation-selector='cert-manager.io/certificate-name' \
    --secrets-annotation-selector='test' \
    --secrets-include-glob='*.crt' \
    --logtostderr &
pid=$!
sleep 10

validateMetrics 'cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"}' 100
validateMetrics 'cert_exporter_secret_expires_in_seconds{cn="hms-test",issuer="hms-test",key_name="test.crt",secret_name="test",secret_namespace="default"}'

# kill exporter
echo "** Killing $pid"
kill $pid

echo "** Testing Label Selector And Namespace"
# run exporter
$CERT_EXPORTER_PATH \
    --kubeconfig=$CONFIG_PATH \
    --secrets-annotation-selector='cert-manager.io/certificate-name' \
    --secrets-namespace='cert-manager-test' \
    --secrets-include-glob='*.crt' \
    --logtostderr &
pid=$!
sleep 10

validateMetrics 'cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"}' 100

# kill exporter
echo "** Killing $pid"
kill $pid

echo "** Testing Label Selector And Exclude Glob"
# run exporter
$CERT_EXPORTER_PATH \
    --kubeconfig=$CONFIG_PATH \
    --secrets-annotation-selector='cert-manager.io/certificate-name' \
    --secrets-namespace='cert-manager-test' \
    --secrets-exclude-glob='*.key' \
    --logtostderr &
pid=$!
sleep 10

validateMetrics 'cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"}' 100

# kill exporter
echo "** Killing $pid"
kill $pid

echo "** Testing ConfigMap checker"
# run exporter
$CERT_EXPORTER_PATH \
    --kubeconfig=$CONFIG_PATH \
    --configmaps-annotation-selector='test' \
    --configmaps-include-glob='*.crt' \
    --logtostderr &
pid=$!
sleep 10

validateMetrics 'cert_exporter_configmap_expires_in_seconds{cn="hms-test",configmap_name="test",configmap_namespace="default",issuer="hms-test",key_name="test.crt"}'

# kill exporter
echo "** Killing $pid"
kill $pid

echo "** Testing Webhook checker"
# run exporter
$CERT_EXPORTER_PATH \
    --kubeconfig=$CONFIG_PATH \
    --enable-webhook-cert-check=true \
    --logtostderr &
pid=$!
sleep 10

validateMetrics 'cert_exporter_webhook_not_after_timestamp{admission_review_version_name="mutating.test-webhook.com",cn="cert-manager-webhook-ca",issuer="cert-manager-webhook-ca",type_name="mutatingwebhookconfiguration",webhook_name="test-webhook-cfg"}'

# kill exporter
echo "** Killing $pid"
kill $pid

echo "** Testing Certrequest Annotation and Namespace Selector"
# run exporter
$CERT_EXPORTER_PATH \
    --kubeconfig=$CONFIG_PATH \
    --certrequests-annotation-selector='cert-manager.io/certificate-name' \
    --certrequests-namespace='cert-manager-test' \
    --logtostderr &
pid=$!
sleep 10

validateMetrics "cert_exporter_certrequest_expires_in_seconds{cert_request=\""$CERT_REQUEST"\",certrequest_namespace=\"cert-manager-test\",cn=\"example.com\",issuer=\"example.com\"}" 100

# kill exporter
echo "** Killing $pid"
kill $pid

echo "** Testing Certrequest Label Selector"
# run exporter
$CERT_EXPORTER_PATH \
    --kubeconfig=$CONFIG_PATH \
    --certrequests-label-selector='testlabel=test' \
    --logtostderr &
pid=$!
sleep 10

validateMetrics "cert_exporter_certrequest_expires_in_seconds{cert_request=\""$CERT_REQUEST"\",certrequest_namespace=\"cert-manager-test\",cn=\"example.com\",issuer=\"example.com\"}" 100

# kill exporter
echo "** Killing $pid"
kill $pid

echo "** Testing Certrequest bool"
# run exporter
$CERT_EXPORTER_PATH \
    --kubeconfig=$CONFIG_PATH \
    --enable-certrequests-check=true \
    --logtostderr &
pid=$!
sleep 10

validateMetrics "cert_exporter_certrequest_expires_in_seconds{cert_request=\""$CERT_REQUEST"\",certrequest_namespace=\"cert-manager-test\",cn=\"example.com\",issuer=\"example.com\"}" 100

# kill exporter
echo "** Killing $pid"
kill $pid

kind delete cluster --name=$KIND_CLUSTER_NAME --kubeconfig=$CONFIG_PATH
rm $CONFIG_PATH
