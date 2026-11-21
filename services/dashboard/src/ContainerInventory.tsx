import { t, useLocale } from "./i18n";
import { useState } from "react";
import { z } from "zod";
import { useData, State, Card, Pagination } from "./ui";
import { date, label } from "./format";

const scan = z.object({
    scope: z.string(),
    target: z.string().nullable(),
    status: z.string(),
    captured_at: z.string(),
    error_code: z.string().nullable(),
    package_count: z.number().nullable(),
    scanner_version: z.string().nullable(),
});
const schema = z.object({
    software_status: z.string().default("not_collected"),
    items: z.array(
        z.object({
            container_id: z.string(),
            name: z.string().nullable(),
            image_id: z.string().nullable(),
            image_reference: z.string(),
            state: z.string(),
            scans: z.array(scan),
        }),
    ),
    total: z.number(),
});
const software = z.object({
    items: z.array(
        z.object({
            scope: z.string(),
            target: z.string().nullable(),
            status: z.string(),
            os: z.record(z.string(), z.unknown()),
            package: z.object({
                name: z.string(),
                version: z.string(),
                type: z.string(),
                purl: z.string().optional(),
            }),
        }),
    ),
    total: z.number(),
});
export default function ContainerInventory({ server }: { server: string }) {
    useLocale();
    const [offset, setOffset] = useState(0);
    const [selected, setSelected] = useState<string | null>(null);
    const result = useData(
        `/api/v1/dashboard/security/servers/${server}/containers?offset=${offset}`,
        schema,
    );
    return (
        <Card title={t("Docker-Container & Software")}>
            <p>
                {t(
                    "Gespeicherter Inventarstand. Gestoppte Container werden angezeigt und erzeugen keine aktiven Softwaretreffer.",
                )}
            </p>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <p>
                        {t("Softwareerfassung:")}{" "}
                        {label(result.data.software_status)}
                    </p>
                    {!result.data.total ? (
                        <p>{t("Keine Container erfasst.")}</p>
                    ) : (
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("Container / Image")}</th>
                                    <th>{t("Zustand")}</th>
                                    <th>{t("Softwareerfassung")}</th>
                                    <th>{t("Pakete")}</th>
                                    <th>{t("Letzte Erfassung")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {result.data.items.map((c) => (
                                    <tr key={c.container_id}>
                                        <td>
                                            <button
                                                onClick={() =>
                                                    setSelected(c.container_id)
                                                }
                                            >
                                                {c.name ??
                                                    c.container_id.slice(0, 12)}
                                            </button>
                                            <br />
                                            {c.image_reference}
                                        </td>
                                        <td>{c.state}</td>
                                        <td>
                                            {c.scans.length
                                                ? c.scans.map((s, i) => (
                                                      <div key={i}>
                                                          {s.scope}
                                                          {s.target
                                                              ? ` (${s.target})`
                                                              : ""}
                                                          : {s.status}
                                                          {s.error_code
                                                              ? ` – ${s.error_code}`
                                                              : ""}
                                                      </div>
                                                  ))
                                                : t("Nicht erfasst")}
                                        </td>
                                        <td>
                                            {c.scans.map((s, i) => (
                                                <div key={i}>
                                                    {s.package_count ?? "–"}
                                                </div>
                                            ))}
                                        </td>
                                        <td>
                                            {c.scans.map((s, i) => (
                                                <div key={i}>
                                                    {date(s.captured_at)}
                                                </div>
                                            ))}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                    <Pagination
                        offset={offset}
                        total={result.data.total}
                        onChange={setOffset}
                    />
                </>
            )}
            {selected && (
                <Software key={selected} server={server} container={selected} />
            )}
        </Card>
    );
}
function Software({
    server,
    container,
}: {
    server: string;
    container: string;
}) {
    useLocale();
    const [offset, setOffset] = useState(0);
    const result = useData(
        `/api/v1/dashboard/security/servers/${server}/container-software?container_id=${encodeURIComponent(container)}&offset=${offset}`,
        software,
    );
    return (
        <section>
            <h3>{t("Erkannte Software")}</h3>
            <p>
                {t(
                    "Image, Laufzeit und eingebundene Anwendungen werden getrennt ausgewiesen. Eine fehlende oder unvollständige Erfassung ist keine Entwarnung.",
                )}
            </p>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <table>
                        <thead>
                            <tr>
                                <th>{t("Paket")}</th>
                                <th>{t("Version")}</th>
                                <th>{t("Typ")}</th>
                                <th>{t("Herkunft")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {result.data.items.map((s, i) => (
                                <tr key={i}>
                                    <td>{s.package.name}</td>
                                    <td>{s.package.version}</td>
                                    <td>{s.package.type}</td>
                                    <td>
                                        {s.scope} {s.target}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    <Pagination
                        limit={50}
                        offset={offset}
                        total={result.data.total}
                        onChange={setOffset}
                    />
                </>
            )}
        </section>
    );
}
