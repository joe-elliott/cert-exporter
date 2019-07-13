pushd ../../

go run main.go --kubeconfig ~/.kube/config --secrets-label-selector 'certmanager.k8s.io/certificate-name' --alsologtostderr

popd