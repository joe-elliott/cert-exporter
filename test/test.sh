rm -rf certs
mkdir certs

./genCerts.sh certs 100
./genKubeConfig.sh certs ./

