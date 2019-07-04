# cleanup
rm *.keys
rm *.csr
rm *.crt
rm ./kubeconfig

# keys
openssl genrsa -out root.key
openssl genrsa -out client.key
openssl genrsa -out server.key

# root cert
openssl req -x509 -new -nodes -key root.key -subj "/C=US/ST=KY/O=Org/CN=root" -sha256 -days 1024 -out root.crt

# csrs
openssl req -new -sha256 -key client.key -subj "/C=US/ST=KY/O=Org/CN=client" -out client.csr
openssl req -new -sha256 -key server.key -subj "/C=US/ST=KY/O=Org/CN=example.com" -out server.csr

openssl x509 -req -in client.csr -CA root.crt -CAkey root.key -CAcreateserial -out client.crt -days 500 -sha256
openssl x509 -req -in server.csr -CA root.crt -CAkey root.key -CAcreateserial -out server.crt -days 500 -sha256

# kubeconfig
kubectl config --kubeconfig=./kubeconfig set-cluster cluster1 --server=https://example.com --certificate-authority=root.crt
kubectl config --kubeconfig=./kubeconfig set-cluster cluster2 --server=https://example.com --certificate-authority=root.crt --embed-certs=true

kubectl config --kubeconfig=./kubeconfig set-credentials user1 --client-certificate=./client.crt --client-key=./client.key
kubectl config --kubeconfig=./kubeconfig set-credentials user2 --client-certificate=./client.crt --client-key=./client.key --embed-certs=true



