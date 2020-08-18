#!/bin/bash

# requires a k8s cluster running with cert-manager running in it
# requires kind https://github.com/kubernetes-sigs/kind

set -o errexit

validateMetrics() {
    metrics=$1
    expectedVal=$2    

    raw=$(curl --silent http://localhost:8080/metrics | grep "$metrics")

    if [ "$raw" == "" ]; then
      echo "TEST FAILURE: $metrics" 
      echo "  Unable to find metrics string"
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

KIND_CLUSTER_NAME=cert-exporter
CONFIG_PATH=cert-exporter.kubeconfig

echo -n "Create cluster"
# cert-manager v1alpha1 is no longer workable on kubernetes version >= v1.18.x
kind create cluster --name=$KIND_CLUSTER_NAME --kubeconfig=$CONFIG_PATH --image=kindest/node:v1.17.0

kubectl --kubeconfig=$CONFIG_PATH create namespace cert-manager
kubectl --kubeconfig=$CONFIG_PATH label namespace cert-manager certmanager.k8s.io/disable-validation=true
kubectl --kubeconfig=$CONFIG_PATH apply -f https://github.com/jetstack/cert-manager/releases/download/v0.10.1/cert-manager.yaml

kubectl --kubeconfig=$CONFIG_PATH wait --for=condition=available deploy --all -n cert-manager --timeout=3m

GO111MODULE=on go mod vendor
go build ../../main.go

kubectl --kubeconfig=$CONFIG_PATH apply -f ./certs.yaml

kubectl --kubeconfig=$CONFIG_PATH wait --for=condition=ready certificate/selfsigned-cert -n cert-manager-test

echo "** Testing Label Selector"
# run exporter
./main --kubeconfig=$CONFIG_PATH \
    --secrets-label-selector='certmanager.k8s.io/certificate-name' \
    --secrets-include-glob='*.crt' \
    --logtostderr &
pid=$!
sleep 10

validateMetrics 'cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"}' 100

# kill exporter
echo "** Killing $pid"
kill $pid

echo "** Testing Label Selector And Namespace"
# run exporter
./main --kubeconfig=$CONFIG_PATH \
    --secrets-label-selector='certmanager.k8s.io/certificate-name' \
    --secrets-namespace='cert-manager-test' \
    --secrets-include-glob='*.crt' \
    --logtostderr &
pid=$!
sleep 10

validateMetrics 'cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"}' 100

# kill exporter
echo "** Killing $pid"
kill $pid

rm ./main
kind delete cluster --name=$KIND_CLUSTER_NAME --kubeconfig=$CONFIG_PATH
rm $CONFIG_PATH
