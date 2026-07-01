{{- define "fides.name" -}}fides{{- end -}}

{{- define "fides.fullname" -}}
{{- printf "%s-%s" .Release.Name "fides" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fides.labels" -}}
app.kubernetes.io/name: {{ include "fides.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: fides-{{ .Chart.Version }}
{{- end -}}

{{- define "fides.secretName" -}}
{{- if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}{{- else -}}{{ include "fides.fullname" . }}-secrets{{- end -}}
{{- end -}}

{{- define "fides.appDSN" -}}
host={{ .Values.database.host }} port={{ .Values.database.port }} user={{ .Values.database.appUser }} password={{ .Values.database.appPassword }} dbname={{ .Values.database.name }} sslmode={{ .Values.database.sslmode }}
{{- end -}}
