{{/* Images: a digest (recommended for production) wins over a tag; the tag defaults to the chart's appVersion. */}}
{{- define "shieldwaf.image" -}}
{{- if .Values.image.digest -}}{{ .Values.image.repository }}@{{ .Values.image.digest }}{{- else -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end -}}
{{- end -}}

{{- define "shieldwaf.dbImage" -}}
{{- if .Values.database.image.digest -}}{{ .Values.database.image.repository }}@{{ .Values.database.image.digest }}{{- else -}}{{ .Values.database.image.repository }}:{{ .Values.database.image.tag | default "16" }}{{- end -}}
{{- end -}}

{{- define "shieldwaf.labels" -}}
app.kubernetes.io/name: shieldwaf
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* The host name of the database service (the bundled one unless an external one is configured). */}}
{{- define "shieldwaf.dbHost" -}}
{{- if .Values.database.bundled -}}shieldwaf-db{{- else -}}{{ .Values.backup.dbHost | default "shieldwaf-db" }}{{- end -}}
{{- end -}}
