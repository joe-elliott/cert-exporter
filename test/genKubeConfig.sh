kubeConfigFolder=$1
certFolder=$2

pushd $kubeConfigFolder

# kubeconfig
kubectl config --kubeconfig=./kubeconfig set-cluster cluster1 --server=https://example.com --certificate-authority=$certFolder/root.crt
kubectl config --kubeconfig=./kubeconfig set-cluster cluster2 --server=https://example.com --certificate-authority=$certFolder/root.crt --embed-certs=true

kubectl config --kubeconfig=./kubeconfig set-credentials user1 --client-certificate=$certFolder/client.crt --client-key=$certFolder/client.key
kubectl config --kubeconfig=./kubeconfig set-credentials user2 --client-certificate=$certFolder/client.crt --client-key=$certFolder/client.key --embed-certs=true

popd