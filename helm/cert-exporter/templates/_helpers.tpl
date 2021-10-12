{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "cert-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "cert-exporter.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cert-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Labels for a generic resource not belonging to the Deployment or DaemonSet
*/}}
{{- define "cert-exporter.genericLabels" -}}
helm.sh/chart: {{ include "cert-exporter.chart" . }}
{{ include "cert-exporter.genericSelectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels for a generic resource not belonging to the Deployment or DaemonSet
*/}}
{{- define "cert-exporter.genericSelectorLabels" -}}
app.kubernetes.io/name: {{ include "cert-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Labels for the Deployment and DaemonSet
*/}}
{{- define "cert-exporter.certManagerLabels" -}}
helm.sh/chart: {{ include "cert-exporter.chart" . }}
{{ include "cert-exporter.certManagerSelectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels for the Deployment and DaemonSet
*/}}
{{- define "cert-exporter.certManagerSelectorLabels" -}}
{{ include "cert-exporter.genericSelectorLabels" . }}
cert-exporter.io/type: {{ kebabcase .Values.certManager.kind }}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "cert-exporter.serviceAccountName" -}}
{{- if .Values.rbac.serviceAccount.create -}}
    {{ default (include "cert-exporter.fullname" .) .Values.rbac.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.rbac.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Check the exporter kind is Deployment or DaemonSet
*/}}
{{- define "certManager.assertValidKind" -}}
{{- if not (or (eq .Values.certManager.kind "DaemonSet") (eq .Values.certManager.kind "Deployment")) -}}
{{- fail "certManager.kind should be one of either Deployment or DaemonSet" -}}
{{- end -}}
{{- end -}}