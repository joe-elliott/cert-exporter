#!/bin/bash

# requires a k8s cluster running with cert-manager running in it
# requires kind https://github.com/kubernetes-sigs/kind

set -o errexit

fetchMetricsTimestampValue() {
    local metrics
    metrics="$1"

    curl --silent http://localhost:8080/metrics \
    | grep -F "$metrics" \
    | awk '{ printf("%.0f",$2) }'
}

validateTimestampBefore() {
    local metrics
    local want
    local got
    metrics="$1"
    want="$2"
    got=$(fetchMetricsTimestampValue "$metrics")

    if [ "$got" == "" ]; then
      echo "TEST FAILURE: $metrics" 
      echo "  Unable to find metrics string"
      return 0
    fi

    if [ "$got" -ge "$want" ]; then
      echo "TEST FAILURE: $metrics"
      echo "  Want      : $want"
      echo "  Got       : $got"
    else 
      echo "TEST SUCCESS: $metrics"
    fi
}

validateMetrics() {
    local metrics
    local expectedVal
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

CERT_EXPORTER_PATH="../../dist/cert-exporter_$(go env GOOS)_$(go env GOARCH)_v1/cert-exporter"

days=${1:-100}
export NODE_NAME="master0"

#
# certs and kubeconfig in the same dir
#
echo "** Testing Certs and kubeconfig in the same dir"
mkdir certs
./genCerts.sh certs $days >/dev/null 2>&1
./genKubeConfig.sh certs ./ >/dev/null 2>&1


# run exporter
$CERT_EXPORTER_PATH -include-cert-glob=certs/*.crt  -include-kubeconfig-glob=certs/kubeconfig &

sleep 2

curl --silent http://localhost:8080/metrics | grep 'cert_exporter_error_total 0'

activation=$(date +%s) # this timestamp is at least 2 seconds off from the actual cert NotBefore attribute ...
validateTimestampBefore 'cert_exporter_cert_not_before_timestamp{cn="client",filename="certs/client.crt",issuer="root",nodename="master0"}' $activation
validateTimestampBefore 'cert_exporter_cert_not_before_timestamp{cn="root",filename="certs/root.crt",issuer="root",nodename="master0"}' $activation
validateTimestampBefore 'cert_exporter_cert_not_before_timestamp{cn="example.com",filename="certs/server.crt",issuer="root",nodename="master0"}' $activation
validateTimestampBefore 'cert_exporter_cert_not_before_timestamp{cn="bundle-root",filename="certs/bundle.crt",issuer="bundle-root",nodename="master0"}' $activation
validateTimestampBefore 'cert_exporter_cert_not_before_timestamp{cn="example-bundle.be",filename="certs/bundle.crt",issuer="bundle-root",nodename="master0"}' $activation
validateTimestampBefore 'cert_exporter_cert_not_before_timestamp{cn="bundle-root",filename="certs/bundle_pfx.crt",issuer="bundle-root",nodename="master0"}' $activation

expiration=$((activation + days * 24 * 60 * 60)) # ... and as a result, this values if off as well
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="client",filename="certs/client.crt",issuer="root",nodename="master0"}' $expiration
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="root",filename="certs/root.crt",issuer="root",nodename="master0"}' $expiration
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="example.com",filename="certs/server.crt",issuer="root",nodename="master0"}' $expiration
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="bundle-root",filename="certs/bundle.crt",issuer="bundle-root",nodename="master0"}' $expiration
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="example-bundle.be",filename="certs/bundle.crt",issuer="bundle-root",nodename="master0"}' $expiration
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="bundle-root",filename="certs/bundle_pfx.crt",issuer="bundle-root",nodename="master0"}' $expiration

validateMetrics 'cert_exporter_cert_expires_in_seconds{cn="client",filename="certs/client.crt",issuer="root",nodename="master0"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{cn="root",filename="certs/root.crt",issuer="root",nodename="master0"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{cn="example.com",filename="certs/server.crt",issuer="root",nodename="master0"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{cn="bundle-root",filename="certs/bundle.crt",issuer="bundle-root",nodename="master0"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{cn="example-bundle.be",filename="certs/bundle.crt",issuer="bundle-root",nodename="master0"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{cn="bundle-root",filename="certs/bundle_pfx.crt",issuer="bundle-root",nodename="master0"}' $days


validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{cn="root",filename="certs/kubeconfig",issuer="root",name="cluster1",nodename="master0",type="cluster"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{cn="root",filename="certs/kubeconfig",issuer="root",name="cluster2",nodename="master0",type="cluster"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{cn="client",filename="certs/kubeconfig",issuer="root",name="user1",nodename="master0",type="user"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{cn="client",filename="certs/kubeconfig",issuer="root",name="user2",nodename="master0",type="user"}' $days

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
$CERT_EXPORTER_PATH -include-cert-glob=certsSibling/*.crt  -include-kubeconfig-glob=kubeConfigSibling/kubeconfig &

sleep 2

curl --silent http://localhost:8080/metrics | grep 'cert_exporter_error_total 0'

activation=$(date +%s) # this timestamp is at least 2 seconds off from the actual cert NotBefore attribute ...
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="client",filename="certsSibling/client.crt",issuer="root",nodename="master0"}' $activation
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="root",filename="certsSibling/root.crt",issuer="root",nodename="master0"}' $activation
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="example.com",filename="certsSibling/server.crt",issuer="root",nodename="master0"}' $activation

expiration=$((activation + days * 24 * 60 * 60)) # ... and as a result, this values if off as well
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="client",filename="certsSibling/client.crt",issuer="root",nodename="master0"}' $expiration
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="root",filename="certsSibling/root.crt",issuer="root",nodename="master0"}' $expiration
validateTimestampBefore 'cert_exporter_cert_not_after_timestamp{cn="example.com",filename="certsSibling/server.crt",issuer="root",nodename="master0"}' $expiration

validateMetrics 'cert_exporter_cert_expires_in_seconds{cn="client",filename="certsSibling/client.crt",issuer="root",nodename="master0"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{cn="root",filename="certsSibling/root.crt",issuer="root",nodename="master0"}' $days
validateMetrics 'cert_exporter_cert_expires_in_seconds{cn="example.com",filename="certsSibling/server.crt",issuer="root",nodename="master0"}' $days

validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{cn="root",filename="kubeConfigSibling/kubeconfig",issuer="root",name="cluster1",nodename="master0",type="cluster"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{cn="root",filename="kubeConfigSibling/kubeconfig",issuer="root",name="cluster2",nodename="master0",type="cluster"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{cn="client",filename="kubeConfigSibling/kubeconfig",issuer="root",name="user1",nodename="master0",type="user"}' $days
validateMetrics 'cert_exporter_kubeconfig_expires_in_seconds{cn="client",filename="kubeConfigSibling/kubeconfig",issuer="root",name="user2",nodename="master0",type="user"}' $days

# kill exporter
kill $!

#
# confirm error metric works
#
echo "** Testing Error metric increments"
echo 'asdfasdf' > certs/client.crt

# run exporter
$CERT_EXPORTER_PATH -include-cert-glob=certs/client.crt &

sleep 2

curl --silent http://localhost:8080/metrics | grep 'cert_exporter_error_total 1'

# kill exporter
kill $!
unset NODE_NAME
