module github.com/joe-elliott/cert-exporter

go 1.12

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/joe-elliott/kubernetes-grafana-controller v0.0.1
	github.com/prometheus/client_golang v1.0.0
	gopkg.in/yaml.v2 v2.2.2
	k8s.io/api v0.0.0-20190712022805-31fe033ae6f9 // indirect
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog v0.3.3
	k8s.io/utils v0.0.0-20190712101616-fac88abaa102 // indirect
)
