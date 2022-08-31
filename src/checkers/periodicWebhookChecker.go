package checkers

import (
	"context"
	"time"

	"github.com/golang/glog"
	v1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

const (
	mutatingWebhookConfigurationType   = "mutatingwebhookconfiguration"
	validatingWebhookConfigurationType = "validatingwebhookconfiguration"
)

// PeriodicWebhookChecker is an object designed to check for mutating webhook and validating webhook cert files at a regular interval
type PeriodicWebhookChecker struct {
	period              time.Duration
	labelSelectors      []string
	kubeconfigPath      string
	annotationSelectors []string
	exporter            *exporters.WebhookExporter
}

// NewWebhookChecker is a factory method that returns a new PeriodicNewWebhookChecker
func NewWebhookChecker(period time.Duration, labelSelectors, annotationSelectors []string, kubeconfigPath string, e *exporters.WebhookExporter) *PeriodicWebhookChecker {
	return &PeriodicWebhookChecker{
		period:              period,
		labelSelectors:      labelSelectors,
		annotationSelectors: annotationSelectors,
		kubeconfigPath:      kubeconfigPath,
		exporter:            e,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicWebhookChecker) StartChecking() {
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

		p.exporter.ResetMetrics()
		p.checkMutatingWebhook(client)
		p.checkValidatingWebhook(client)
		<-periodChannel
	}
}

func (p *PeriodicWebhookChecker) checkMutatingWebhook(client kubernetes.Interface) {
	var configs []v1.MutatingWebhookConfiguration
	var err error
	if len(p.labelSelectors) > 0 {
		for _, labelSelector := range p.labelSelectors {
			var m *v1.MutatingWebhookConfigurationList
			m, err = client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(context.TODO(), metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			if err != nil {
				break
			}

			configs = append(configs, m.Items...)
		}
	} else {
		var m *v1.MutatingWebhookConfigurationList
		m, err = client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(context.TODO(), metav1.ListOptions{})
		if err == nil {
			configs = m.Items
		}
	}

	if err != nil {
		glog.Errorf("Error requesting mutatingwebhookconfiguration %v", err)
		metrics.ErrorTotal.Inc()
		return
	}

	for _, configuration := range configs {
		glog.Infof("Reviewing mutatingwebhookconfiguration %v", configuration.GetName())
		if len(p.annotationSelectors) > 0 {
			matches := false
			annotations := configuration.GetAnnotations()
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
		glog.Infof("Annotations matched. Parsing mutatingwebhookconfiguration.")

		for _, admissionReviewVersions := range configuration.Webhooks {
			if len(admissionReviewVersions.ClientConfig.CABundle) > 0 {
				glog.Infof("Publishing %v metrics", configuration.Name)
				err = p.exporter.ExportMetrics(admissionReviewVersions.ClientConfig.CABundle, mutatingWebhookConfigurationType, configuration.Name, admissionReviewVersions.Name)
				if err != nil {
					glog.Errorf("Error exporting mutatingwebhookconfiguration %v", err)
					metrics.ErrorTotal.Inc()
				}
			} else {
				glog.Infof("Ignoring %v. Does not contains CABundle cert", configuration.Name)
			}
		}
	}
}

func (p *PeriodicWebhookChecker) checkValidatingWebhook(client kubernetes.Interface) {
	var configs []v1.ValidatingWebhookConfiguration
	var err error
	if len(p.labelSelectors) > 0 {
		for _, labelSelector := range p.labelSelectors {
			var v *v1.ValidatingWebhookConfigurationList
			v, err = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(context.TODO(), metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			if err != nil {
				break
			}

			configs = append(configs, v.Items...)
		}
	} else {
		var v *v1.ValidatingWebhookConfigurationList
		v, err = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(context.TODO(), metav1.ListOptions{})
		if err == nil {
			configs = v.Items
		}
	}

	if err != nil {
		glog.Errorf("Error requesting validatingwebhookconfiguration %v", err)
		metrics.ErrorTotal.Inc()
		return
	}

	for _, configuration := range configs {
		glog.Infof("Reviewing validatingwebhookconfiguration %v", configuration.GetName())
		if len(p.annotationSelectors) > 0 {
			matches := false
			annotations := configuration.GetAnnotations()
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
		glog.Infof("Annotations matched. Parsing validatingwebhookconfiguration.")

		for _, admissionReviewVersions := range configuration.Webhooks {
			if len(admissionReviewVersions.ClientConfig.CABundle) > 0 {
				glog.Infof("Publishing %v metrics", configuration.Name)
				err = p.exporter.ExportMetrics(admissionReviewVersions.ClientConfig.CABundle, validatingWebhookConfigurationType, configuration.Name, admissionReviewVersions.Name)
				if err != nil {
					glog.Errorf("Error exporting validatingwebhookconfiguration %v", err)
					metrics.ErrorTotal.Inc()
				}
			} else {
				glog.Infof("Ignoring %v. Does not contains CABundle cert", configuration.Name)
			}
		}
	}
}
