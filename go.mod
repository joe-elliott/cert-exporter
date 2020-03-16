module github.com/joe-elliott/cert-exporter

go 1.14

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/googleapis/gnostic v0.3.0 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/prometheus/client_golang v1.0.0
	github.com/spf13/pflag v1.0.3 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 // indirect
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.2.2
	k8s.io/api v0.0.0-20190712022805-31fe033ae6f9
	k8s.io/apimachinery v0.0.0-20190711222657-391ed67afa7b
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/utils v0.0.0-20190712101616-fac88abaa102 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)

replace (
	k8s.io/api => k8s.io/api v0.0.0-20190816222004-e3a6b8045b0b
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190816221834-a9f1d8a9c101
	k8s.io/client-go => k8s.io/client-go v11.0.1-0.20190820062731-7e43eff7c80a+incompatible
)
