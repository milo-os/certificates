export const API_GROUP = "certificates.miloapis.com";
export const API_VERSION = "v1alpha1";
export const RESOURCES_BASE = `/apis/${API_GROUP}/${API_VERSION}`;

export function tlscertificatesPath(namespace = "default") {
  return `${RESOURCES_BASE}/namespaces/${namespace}/tlscertificates`;
}

export function tlscertificatePath(name: string, namespace = "default") {
  return `${RESOURCES_BASE}/namespaces/${namespace}/tlscertificates/${name}`;
}
