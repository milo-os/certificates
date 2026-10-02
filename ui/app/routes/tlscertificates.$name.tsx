import { json } from "@remix-run/node";
import type { LoaderFunctionArgs } from "@remix-run/node";
import { useLoaderData } from "@remix-run/react";
import { Badge } from "@datum-cloud/datum-ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@datum-cloud/datum-ui/card";
import { PageTitle } from "@datum-cloud/datum-ui/page-title";
import { fetchK8s } from "~/lib/k8s.server";
import { phaseBadgeProps, relativeAge } from "~/lib/format";
import type { TLSCertificate } from "~/lib/types";
import { tlscertificatePath } from "~/lib/api";

interface LoaderData {
  tlscertificate: TLSCertificate | null;
  error?: string;
}

export async function loader({ request, params }: LoaderFunctionArgs) {
  const name = params.name ?? "";
  try {
    // TLSCertificates are namespaced — list all and find by name for the template.
    // In practice, scope this to a specific namespace via query param or config.
    const tlscertificate = await fetchK8s<TLSCertificate>(
      request,
      tlscertificatePath(encodeURIComponent(name))
    );
    return json({ tlscertificate } satisfies LoaderData);
  } catch (e) {
    return json({
      tlscertificate: null,
      error: e instanceof Error ? e.message : String(e),
    } satisfies LoaderData);
  }
}

export default function TLSCertificateDetail() {
  const { tlscertificate, error } = useLoaderData<typeof loader>() as LoaderData;

  if (error || !tlscertificate) {
    return (
      <div className="px-6 py-4">
        <Card>
          <CardContent className="py-6">
            <p className="text-sm font-medium">Failed to load tlscertificate</p>
            <p className="text-sm text-muted-foreground mt-1">{error}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const phase = tlscertificate.status?.phase;
  const badge = phase ? phaseBadgeProps(phase) : null;

  return (
    <div className="flex flex-col gap-4 px-6 py-4">
      <div className="flex items-center gap-3">
        <PageTitle title={tlscertificate.metadata.name} actionsPosition="inline" />
        {badge && phase && (
          <Badge type={badge.type} theme={badge.theme}>
            {phase}
          </Badge>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Details</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Namespace</dt>
                <dd>{tlscertificate.metadata.namespace ?? "—"}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Age</dt>
                <dd>{relativeAge(tlscertificate.metadata.creationTimestamp)}</dd>
              </div>
              {tlscertificate.spec.description && (
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Description</dt>
                  <dd className="text-right max-w-[60%]">{tlscertificate.spec.description}</dd>
                </div>
              )}
            </dl>
          </CardContent>
        </Card>

        {tlscertificate.status?.conditions && tlscertificate.status.conditions.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Conditions</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="space-y-2 text-sm">
                {tlscertificate.status.conditions.map((c) => (
                  <div key={c.type} className="flex justify-between">
                    <dt className="text-muted-foreground">{c.type}</dt>
                    <dd className="flex items-center gap-2">
                      <span
                        className={
                          c.status === "True"
                            ? "text-green-600 dark:text-green-400"
                            : "text-muted-foreground"
                        }
                      >
                        {c.status}
                      </span>
                      {c.reason && (
                        <span className="text-muted-foreground">({c.reason})</span>
                      )}
                    </dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
