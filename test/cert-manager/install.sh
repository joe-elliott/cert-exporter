# https://docs.cert-manager.io/en/latest/getting-started/install/kubernetes.html

kubectl create namespace cert-manager
kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.8.1/cert-manager.yaml

kubectl create -f certs.yaml

# labels:
#   certmanager.k8s.io/certificate-name: selfsigned-cert

# Name:         selfsigned-cert-tls
# Namespace:    cert-manager-test
# Labels:       certmanager.k8s.io/certificate-name=selfsigned-cert
# Annotations:  certmanager.k8s.io/alt-names: example.com
#               certmanager.k8s.io/common-name: example.com
#               certmanager.k8s.io/ip-sans: 
#               certmanager.k8s.io/issuer-kind: Issuer
#               certmanager.k8s.io/issuer-name: test-selfsigned

# Type:  kubernetes.io/tls

# Data
# ====
# ca.crt:   1139 bytes
# tls.crt:  1139 bytes
# tls.key:  1675 bytes

# cert data is base64 encoded pem