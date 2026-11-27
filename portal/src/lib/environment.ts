export function runtimeTypeLabel(type: string) {
  switch (type) {
    case "cloud-run": return "Cloud Run";
    case "azure-apps": return "Azure Apps";
    case "s3": return "S3";
    default: return type;
  }
}
