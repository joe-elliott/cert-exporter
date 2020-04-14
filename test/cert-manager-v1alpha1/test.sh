#
# requires a k8s cluster running with cert-manager running in it
#  assumes the location of kubeconfig at $HOME/.kube/config
# requires kind https://github.com/kubernetes-sigs/kind
#

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

echo -n "Create cluster"
kind create cluster --name=$KIND_CLUSTER_NAME

echo -n "Get kubeconfig"
kind export kubeconfig --name=$KIND_CLUSTER_NAME

kubectl --kubeconfig=$HOME/.kube/config create namespace cert-manager
kubectl --kubeconfig=$HOME/.kube/config label namespace cert-manager certmanager.k8s.io/disable-validation=true
kubectl --kubeconfig=$HOME/.kube/config apply -f https://github.com/jetstack/cert-manager/releases/download/v0.10.1/cert-manager.yaml

kubectl --kubeconfig=$HOME/.kube/config wait --for=condition=available deploy --all -n cert-manager --timeout=3m

GO111MODULE=on go mod vendor
go build ../../main.go

kubectl --kubeconfig=$HOME/.kube/config create -f ./certs.yaml

kubectl --kubeconfig=$HOME/.kube/config wait --for=condition=ready certificate/selfsigned-cert -n cert-manager-test

echo "** Testing Label Selector"
# run exporter
./main --kubeconfig=$HOME/.kube/config \
    --secrets-label-selector='certmanager.k8s.io/certificate-name' \
    --secrets-include-glob='*.crt' \
    --alsologtostderr &
pid=$!
sleep 10

validateMetrics 'cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"}' 100

# kill exporter
echo "** Killing $pid"
kill $pid

echo "** Testing Label Selector And Namespace"
# run exporter
./main --kubeconfig=$HOME/.kube/config \
    --secrets-label-selector='certmanager.k8s.io/certificate-name' \
    --secrets-namespace='cert-manager-test' \
    --secrets-include-glob='*.crt' \
    --alsologtostderr &
pid=$!
sleep 10

validateMetrics 'cert_exporter_secret_expires_in_seconds{cn="example.com",issuer="example.com",key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"}' 100

# kill exporter
echo "** Killing $pid"
kill $pid

rm ./main
kind delete cluster --name=$KIND_CLUSTER_NAME
