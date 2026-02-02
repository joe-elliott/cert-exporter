package checkers

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"log/slog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/joe-elliott/cert-exporter/src/exporters"
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// PeriodicConfigMapChecker is an object designed to check for files on disk at a regular interval
type PeriodicConfigMapChecker struct {
	period                     time.Duration
	labelSelectors             []string
	kubeconfigPath             string
	annotationSelectors        []string
	namespaces                 []string
	exporter                   *exporters.ConfigMapExporter
	includeConfigMapsDataGlobs []string
	excludeConfigMapsDataGlobs []string
	nsLabelSelector            []string
}

// NewConfigMapChecker is a factory method that returns a new PeriodicConfigMapChecker
func NewConfigMapChecker(period time.Duration, labelSelectors, includeConfigMapsDataGlobs, excludeConfigMapsDataGlobs, annotationSelectors, namespaces, nsLabelSelector []string, kubeconfigPath string, e *exporters.ConfigMapExporter) *PeriodicConfigMapChecker {
	return &PeriodicConfigMapChecker{
		period:                     period,
		labelSelectors:             labelSelectors,
		annotationSelectors:        annotationSelectors,
		namespaces:                 namespaces,
		kubeconfigPath:             kubeconfigPath,
		exporter:                   e,
		includeConfigMapsDataGlobs: includeConfigMapsDataGlobs,
		excludeConfigMapsDataGlobs: excludeConfigMapsDataGlobs,
		nsLabelSelector:            nsLabelSelector,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicConfigMapChecker) StartChecking() {
	config, err := clientcmd.BuildConfigFromFlags("", p.kubeconfigPath)
	if err != nil {
		slog.Error("Error building kubeconfig", "error", err)
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		slog.Error("kubernetes.NewForConfig failed", "error", err)
	}

	periodChannel := time.Tick(p.period)

	if strings.Join(p.namespaces, ", ") != "" {
		slog.Info("Scan configMaps", "target", strings.Join(p.namespaces, ", "))
	}
	for {
		slog.Info("Begin periodic check")

		p.exporter.ResetMetrics()

		var configMaps []corev1.ConfigMap
		var namespacesToCheck []string

		if len(p.nsLabelSelector) > 0 { // re-discover namespaces each tick to notice new NSs
			for _, nsLabelSelector := range p.nsLabelSelector {
				var nss *corev1.NamespaceList
				nss, err = client.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{
					LabelSelector: nsLabelSelector,
				})
				if err != nil {
					slog.Error("Error requesting namespaces", "error", err)
					metrics.ErrorTotal.Inc()
				}

				for _, ns := range nss.Items {
					namespacesToCheck = append(namespacesToCheck, ns.GetObjectMeta().GetName())
					slog.Info("Adding namespace to check", "namespace", ns.GetObjectMeta().GetName())
				}
			}
		} else {
			namespacesToCheck = p.namespaces
		}

		for _, ns := range namespacesToCheck {
			if len(p.labelSelectors) > 0 {
				for _, labelSelector := range p.labelSelectors {
					var c *corev1.ConfigMapList
					c, err = client.CoreV1().ConfigMaps(ns).List(context.TODO(), metav1.ListOptions{
						LabelSelector: labelSelector,
					})
					if err != nil {
						slog.Error("Error requesting configMaps", "error", err)
						metrics.ErrorTotal.Inc()
						continue
					}
					configMaps = append(configMaps, c.Items...)
				}
			} else {
				var c *corev1.ConfigMapList
				c, err = client.CoreV1().ConfigMaps(ns).List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					slog.Error("Error requesting configMaps", "error", err)
					metrics.ErrorTotal.Inc()
					continue
				}
				configMaps = append(configMaps, c.Items...)
			}
		}

		for _, configMap := range configMaps {
			include, exclude := false, false
			slog.Info("Reviewing configMap", "name", configMap.GetName(), "namespace", configMap.GetNamespace())

			if len(p.annotationSelectors) > 0 {
				matches := false
				annotations := configMap.GetAnnotations()
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
			slog.Info("Annotations matched. Parsing configMap.")

			for name, data := range configMap.Data {
				include, exclude = false, false

				for _, glob := range p.includeConfigMapsDataGlobs {
					include, err = filepath.Match(glob, name)
					if err != nil {
						slog.Error("Error matching glob", "glob", glob, "name", name, "error", err)
						metrics.ErrorTotal.Inc()
						continue
					}

					if include {
						break
					}
				}

				for _, glob := range p.excludeConfigMapsDataGlobs {
					exclude, err = filepath.Match(glob, name)
					if err != nil {
						slog.Error("Error matching glob", "glob", glob, "name", name, "error", err)
						metrics.ErrorTotal.Inc()
						continue
					}

					if exclude {
						break
					}
				}

				if include && !exclude {
					slog.Info("Publishing metrics", "secret", configMap.Name, "namespace", configMap.Namespace, "key", name)
					err = p.exporter.ExportMetrics([]byte(data), name, configMap.Name, configMap.Namespace)
					if err != nil {
						slog.Error("Error exporting configMap", "error", err)
						metrics.ErrorTotal.Inc()
					}
				} else {
					slog.Info("Ignoring key - does not match filters", "key", name, "include_globs", p.includeConfigMapsDataGlobs, "exclude_globs", p.excludeConfigMapsDataGlobs)
				}
			}
		}

		<-periodChannel
	}
}
