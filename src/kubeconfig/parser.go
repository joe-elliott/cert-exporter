package kubeconfig

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type KubeConfig struct {
	Clusters []struct {
		Name    string
		Cluster struct {
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		}
	}
	Users []struct {
		Name string
		User struct {
			ClientCertificate     string `yaml:"client-certificate"`
			ClientCertificateData string `yaml:"client-certificate-data"`
		}
	}
}

func ParseKubeConfig(file string) (*KubeConfig, error) {
	k := &KubeConfig{}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal([]byte(data), k)
	if err != nil {
		return nil, err
	}

	return k, nil
}
