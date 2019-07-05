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

# cleanup certs
./testCleanup.sh

# build
go build ../main.go
chmod +x main

days=${1:-100}

#
# certs and kubeconfig in the same dir
#
echo "** Testing Certs and kubeconfig in the same dir"
mkdir certs
./genCerts.sh certs $days >/dev/null 2>&1
./genKubeConfig.sh certs ./ >/dev/null 2>&1

# run exporter
./main -include-cert-glob=certs/*.crt  -include-kubeconfig-glob=certs/kubeconfig &

sleep 5

curl --silent http://localhost:8080/metrics | grep 'cert_exporter_error_total 0'

validateMetrics 'cert_exporter_cert_expires_in_seconds{filename="certs/client.crt"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{filename="certs/root.crt"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{filename="certs/server.crt"}' $days

validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="cluster1",type="cluster"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="cluster2",type="cluster"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="user1",type="user"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="user2",type="user"}' $days

# kill exporter
kill $!

#
# certs and kubeconfig in the same dir
#
echo "** Testing Certs and kubeconfig in sibling dirs"
mkdir certsSibling
mkdir kubeConfigSibling
./genCerts.sh certsSibling $days >/dev/null 2>&1
./genKubeConfig.sh kubeConfigSibling ../certsSibling >/dev/null 2>&1

# run exporter
./main -include-cert-glob=certsSibling/*.crt  -include-kubeconfig-glob=kubeConfigSibling/kubeconfig &

sleep 5

curl --silent http://localhost:8080/metrics | grep 'cert_exporter_error_total 0'

validateMetrics 'cert_exporter_cert_expires_in_seconds{filename="certsSibling/client.crt"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{filename="certsSibling/root.crt"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{filename="certsSibling/server.crt"}' $days

validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="cluster1",type="cluster"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="cluster2",type="cluster"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="user1",type="user"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{filename="kubeConfigSibling/kubeconfig",name="user2",type="user"}' $days

# kill exporter
kill $!

