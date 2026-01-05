package checkers

import (
	"context"
	"strings"
	"time"

	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmClientSet "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"log/slog"
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
		slog.Error("Error building kubeconfig", "error", err)
	}

	// creates the certmanager client
	certmanagerClient, err := cmClientSet.NewForConfig(config)
	if err != nil {
		slog.Error("certmanager.NewForConfig failed", "error", err)
	}

	periodChannel := time.Tick(p.period)
	if strings.Join(p.namespaces, ", ") != "" {
		slog.Info("Scan certrequests", "target", strings.Join(p.namespaces, ", "))
	}
	for {
		slog.Info("Begin periodic check")

		p.exporter.ResetMetrics()

		var certrequests []cmapiv1.CertificateRequest

		for _, ns := range p.namespaces {
			var c *cmapiv1.CertificateRequestList

			if len(p.labelSelectors) > 0 {
				for _, labelSelector := range p.labelSelectors {
					c, err = certmanagerClient.CertificateRequests(ns).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
					if err != nil {
						slog.Error("Error requesting certrequest", "error", err)
						metrics.ErrorTotal.Inc()
						continue
					}
					certrequests = append(certrequests, c.Items...)
				}
			} else {
				c, err = certmanagerClient.CertificateRequests(ns).List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					slog.Error("Error requesting certrequest", "error", err)
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
				slog.Info("Ignoring certrequest - not ready", "name", certrequest.GetName(), "namespace", certrequest.GetNamespace())
				continue
			}

			slog.Info("Reviewing certrequest", "name", certrequest.GetName(), "namespace", certrequest.GetNamespace())

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
			slog.Info("Annotations matched. Parsing certrequest.")

			slog.Info("Publishing metrics", "name", certrequest.Name, "namespace", certrequest.Namespace)
			err = p.exporter.ExportMetrics(certrequest.Status.Certificate, certrequest.Name, certrequest.Namespace)
			if err != nil {
				slog.Error("Error exporting certrequest", "error", err)
				metrics.ErrorTotal.Inc()
			}

		}

		<-periodChannel
	}
}
