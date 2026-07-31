{{- define "reporter.validate" -}}
{{- if not .Values.fides.serverUrl -}}
{{- fail "fides.serverUrl is required (e.g. https://fides.example.com)" -}}
{{- end -}}
{{- if not .Values.fides.environmentId -}}
{{- fail "fides.environmentId is required — the Fides environment UUID to report into" -}}
{{- end -}}
{{- if and (eq .Values.serviceAccount.permissionScope "namespace") (not .Values.fides.namespace) -}}
{{- fail "fides.namespace is required when serviceAccount.permissionScope is \"namespace\" (the reporter reads only that namespace)" -}}
{{- end -}}
{{- if not (or (eq .Values.serviceAccount.permissionScope "cluster") (eq .Values.serviceAccount.permissionScope "namespace")) -}}
{{- fail "serviceAccount.permissionScope must be \"cluster\" or \"namespace\"" -}}
{{- end -}}
{{- end -}}
