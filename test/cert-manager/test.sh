#
# requires a k8s cluster running with cert-manager running in it
#  assumes the location of kubeconfig at ~/.kube/config
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
    valInDays=$(awk "BEGIN {print $val / (24 * 60 * 60)}")

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

kubectl delete -f ./certs.yaml
kubectl create -f ./certs.yaml

# run exporter
go run ../../main.go --kubeconfig ~/.kube/config \
               --secrets-label-selector 'certmanager.k8s.io/certificate-name' \
               --alsologtostderr &

sleep 5

validateMetrics 'cert_exporter_secret_expires_in_seconds{key_name="ca.crt",secret_name="selfsigned-cert-tls",secret_namespace="cert-manager-test"}' 100

# kill exporter
kill $!

kubectl delete -f ./certs.yaml