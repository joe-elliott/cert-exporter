# https://docs.cert-manager.io/en/latest/getting-started/install/kubernetes.html

kubectl create namespace cert-manager
kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.8.1/cert-manager.yaml

kubectl create -f certs.yaml
