package checkers

import (
	"path/filepath"
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// PeriodicSecretChecker is an object designed to check for files on disk at a regular interval
type PeriodicSecretChecker struct {
	period                  time.Duration
	labelSelectors          []string
	kubeconfigPath          string
	annotationSelectors     []string
	namespace               string
	exporter                *exporters.SecretExporter
	includeSecretsDataGlobs []string
	excludeSecretsDataGlobs []string
	includeFullCertChain    bool
}

// NewSecretChecker is a factory method that returns a new PeriodicSecretChecker
func NewSecretChecker(period time.Duration, labelSelectors, includeSecretsDataGlobs, excludeSecretsDataGlobs, annotationSelectors []string, namespace, kubeconfigPath string, includeFullCertChain bool, e *exporters.SecretExporter) *PeriodicSecretChecker {
	return &PeriodicSecretChecker{
		period:                  period,
		labelSelectors:          labelSelectors,
		annotationSelectors:     annotationSelectors,
		namespace:               namespace,
		kubeconfigPath:          kubeconfigPath,
		exporter:                e,
		includeSecretsDataGlobs: includeSecretsDataGlobs,
		excludeSecretsDataGlobs: excludeSecretsDataGlobs,
		includeFullCertChain:    includeFullCertChain,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicSecretChecker) StartChecking() {
	config, err := clientcmd.BuildConfigFromFlags("", p.kubeconfigPath)
	if err != nil {
		glog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Fatalf("kubernetes.NewForConfig failed: %v", err)
	}

	periodChannel := time.Tick(p.period)

	for {
		glog.Info("Begin periodic check")

		var secrets []corev1.Secret
		if len(p.labelSelectors) > 0 {
			for _, labelSelector := range p.labelSelectors {
				var s *corev1.SecretList
				s, err = client.CoreV1().Secrets(p.namespace).List(metav1.ListOptions{
					LabelSelector: labelSelector,
				})
				if err != nil {
					break
				}

				secrets = append(secrets, s.Items...)
			}
		} else {
			var s *corev1.SecretList
			s, err = client.CoreV1().Secrets(p.namespace).List(metav1.ListOptions{})
			if err == nil {
				secrets = s.Items
			}
		}

		if err != nil {
			glog.Errorf("Error requesting secrets %v", err)
			metrics.ErrorTotal.Inc()
			continue
		}

		for _, secret := range secrets {
			glog.Infof("Reviewing secret %v in %v", secret.GetName(), secret.GetNamespace())

			if len(p.annotationSelectors) > 0 {
				matches := false
				annotations := secret.GetAnnotations()
				for _, selector := range p.annotationSelectors {
					_, ok := annotations[selector]
					if ok {
						matches = true
						break
					}
				}

				if !matches {
					continue
				}
			}
			glog.Infof("Annotations matched. Parsing Secret.")

			for name, bytes := range secret.Data {
				include, exclude := false, false

				for _, glob := range p.includeSecretsDataGlobs {
					include, err = filepath.Match(glob, name)
					if err != nil {
						glog.Errorf("Error matching %v to %v: %v", glob, name, err)
						metrics.ErrorTotal.Inc()
						continue
					}

					if include {
						break
					}
				}

				for _, glob := range p.excludeSecretsDataGlobs {
					exclude, err = filepath.Match(glob, name)
					if err != nil {
						glog.Errorf("Error matching %v to %v: %v", glob, name, err)
						metrics.ErrorTotal.Inc()
						continue
					}

					if exclude {
						break
					}
				}

				if include && !exclude {
					glog.Infof("Publishing %v/%v metrics %v", secret.Name, secret.Namespace, name)
					err = p.exporter.ExportMetrics(bytes, name, secret.Name, secret.Namespace, p.includeFullCertChain)
					if err != nil {
						glog.Errorf("Error exporting secret %v", err)
						metrics.ErrorTotal.Inc()
					}
				} else {
					glog.Infof("Ignoring %v. Does not match %v or matches %v.", name, p.includeSecretsDataGlobs, p.excludeSecretsDataGlobs)
				}
			}
		}

		<-periodChannel
	}
}
