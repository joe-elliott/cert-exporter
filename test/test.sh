set -e

# cleanup certs
rm -rf certs
mkdir certs
rm -f main

# build
go build ../main.go
chmod +x main

./genCerts.sh certs 100
./genKubeConfig.sh certs ./

# run exporter
./main -include-cert-glob=certs/*.crt  -include-kubeconfig-glob=certs/kubeconfig &

sleep 5

curl --silent http://localhost:8080/metrics | grep 'cert_exporter_error_total 0'

curl --silent http://localhost:8080/metrics | grep 'cert_exporter_cert_expires_in_seconds{filename="certs/client.crt"}'
curl --silent http://localhost:8080/metrics | grep 'cert_exporter_cert_expires_in_seconds{filename="certs/root.crt"}'
curl --silent http://localhost:8080/metrics | grep 'cert_exporter_cert_expires_in_seconds{filename="certs/server.crt"}'

curl --silent http://localhost:8080/metrics | grep 'cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="cluster1",type="cluster"}'
curl --silent http://localhost:8080/metrics | grep 'cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="cluster2",type="cluster"}'
curl --silent http://localhost:8080/metrics | grep 'cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="user1",type="user"}'
curl --silent http://localhost:8080/metrics | grep 'cert_exporter_kubeconfig_expires_in_seconds{filename="certs/kubeconfig",name="user2",type="user"}'

# kill exporter
kill $!