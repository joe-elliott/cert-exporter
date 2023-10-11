package checkers

import (
	"context"
	"strings"
	"time"

	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmClientSet "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// PeriodicCertRequestChecker is an object designed to check for files on disk at a regular interval
type PeriodicCertRequestChecker struct {
	period              time.Duration
	labelSelectors      []string
	kubeconfigPath      string
	annotationSelectors []string
	namespaces          []string
	exporter            *exporters.CertRequestExporter
}

// NewCertRequestChecker is a factory method that returns a new PeriodicCertRequestChecker
func NewCertRequestChecker(period time.Duration, labelSelectors, annotationSelectors, namespaces []string, kubeconfigPath string, e *exporters.CertRequestExporter) *PeriodicCertRequestChecker {
	return &PeriodicCertRequestChecker{
		period:              period,
		labelSelectors:      labelSelectors,
		annotationSelectors: annotationSelectors,
		namespaces:          namespaces,
		kubeconfigPath:      kubeconfigPath,
		exporter:            e,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicCertRequestChecker) StartChecking() {
	config, err := clientcmd.BuildConfigFromFlags("", p.kubeconfigPath)
	if err != nil {
		glog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	// creates the certmanager client
	certmanagerClient, err := cmClientSet.NewForConfig(config)
	if err != nil {
		glog.Fatalf("certmanager.NewForConfig failed: %v", err)
	}

	periodChannel := time.Tick(p.period)
	if strings.Join(p.namespaces, ", ") != "" {
		glog.Infof("Scan certrequests in %v", strings.Join(p.namespaces, ", "))
	}
	for {
		glog.Info("Begin periodic check")

		p.exporter.ResetMetrics()

		var certrequests []cmapiv1.CertificateRequest

		for _, ns := range p.namespaces {
			var c *cmapiv1.CertificateRequestList

			if len(p.labelSelectors) > 0 {
				for _, labelSelector := range p.labelSelectors {
					c, err = certmanagerClient.CertificateRequests(ns).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
					if err != nil {
						glog.Errorf("Error requesting certrequest %v", err)
						metrics.ErrorTotal.Inc()
						continue
					}
					certrequests = append(certrequests, c.Items...)
				}
			} else {
				c, err = certmanagerClient.CertificateRequests(ns).List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					glog.Errorf("Error requesting certrequest %v", err)
					metrics.ErrorTotal.Inc()
					continue
				}
				certrequests = append(certrequests, c.Items...)
			}
		}

		for _, certrequest := range certrequests {
			include := false
			for _, condition := range certrequest.Status.Conditions {
				// Include only certrequests that issued a certificate successfully
				if condition.Type == "Ready" && condition.Status == "True" {
					include = true
					break
				}
			}
			if !include {
				glog.Infof("Ignoring certrequest %s in %s because it is not ready", certrequest.GetName(), certrequest.GetNamespace())
				continue
			}

			glog.Infof("Reviewing certrequest %v in %v", certrequest.GetName(), certrequest.GetNamespace())

			if len(p.annotationSelectors) > 0 {
				matches := false
				annotations := certrequest.GetAnnotations()
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
			glog.Infof("Annotations matched. Parsing certrequest.")

			glog.Infof("Publishing %v/%v metrics", certrequest.Name, certrequest.Namespace)
			err = p.exporter.ExportMetrics(certrequest.Status.Certificate, certrequest.Name, certrequest.Namespace)
			if err != nil {
				glog.Errorf("Error exporting certrequest %v", err)
				metrics.ErrorTotal.Inc()
			}

		}

		<-periodChannel
	}
}
