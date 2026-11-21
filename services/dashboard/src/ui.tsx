import { translateMessage, t, localized, useLocale } from "./i18n";
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { z } from "zod";
import AffectedSoftware from "./AffectedSoftware";
import Threat from "./Threat";
import type { Finding } from "./contracts";
import { api, ApiError } from "./api";
import { date, number, labels, safeLink, percent } from "./format";
export function useData<T>(
    path: string,
    schema: z.ZodType<T>,
    options: {
        refreshInterval?: number;
        refreshEvent?: string;
        changeEvent?: string;
        initialDelay?: number;
    } = {},
) {
    const [data, setData] = useState<T | null>(null);
    const [error, setError] = useState<Error | null>(null);
    const [version, reload] = useState(0);
    const {
        refreshInterval = 0,
        refreshEvent,
        changeEvent,
        initialDelay = 0,
    } = options;
    useEffect(() => {
        if (!refreshEvent) return;
        const refresh = () => reload((value) => value + 1);
        window.addEventListener(refreshEvent, refresh);
        return () => window.removeEventListener(refreshEvent, refresh);
    }, [refreshEvent]);
    useEffect(() => {
        const c = new AbortController();
        let timer: ReturnType<typeof setTimeout> | undefined;
        let loading = false;
        let pending = false;
        setData(null);
        setError(null);
        async function load() {
            if (c.signal.aborted) return;
            if (loading) {
                pending = true;
                return;
            }
            loading = true;
            clearTimeout(timer);
            try {
                const value = await api(path, schema, { signal: c.signal });
                if (!c.signal.aborted) {
                    setData(value);
                    setError(null);
                }
            } catch (problem) {
                if (!c.signal.aborted)
                    setError(
                        problem instanceof Error ? problem : new ApiError(0),
                    );
            } finally {
                loading = false;
                if (!c.signal.aborted && (pending || refreshInterval > 0)) {
                    timer = setTimeout(
                        () => void load(),
                        pending ? 0 : refreshInterval,
                    );
                    pending = false;
                }
            }
        }
        const changed = () => {
            void load();
        };
        if (changeEvent) window.addEventListener(changeEvent, changed);
        if (initialDelay > 0)
            timer = setTimeout(() => void load(), initialDelay);
        else void load();
        return () => {
            if (changeEvent) window.removeEventListener(changeEvent, changed);
            c.abort();
            clearTimeout(timer);
        };
    }, [path, schema, version, refreshInterval, changeEvent, initialDelay]);
    return {
        data,
        error,
        reload: () => {
            setData(null);
            setError(null);
            reload((value) => value + 1);
        },
    };
}
export function State({
    error,
    reload,
}: {
    error: Error | null;
    reload: () => void;
}) {
    useLocale();
    return error ? (
        <div role="alert" className="notice">
            <h2>{t("Daten nicht verfügbar")}</h2>
            <p>{translateMessage(error.message)}</p>
            <button onClick={reload}>{t("Erneut versuchen")}</button>
        </div>
    ) : (
        <p role="status" className="notice">
            {t("Daten werden geladen …")}
        </p>
    );
}
export function Badge({ value }: { value: unknown }) {
    useLocale();
    const text = typeof value === "string" ? value : "unknown";
    return (
        <span className={`badge badge-${text.replace(/[^a-z_]/g, "")}`}>
            {labels[text] ?? text}
        </span>
    );
}
export function Card({
    title,
    children,
}: {
    title: string;
    children: ReactNode;
}) {
    useLocale();
    return (
        <section className="card">
            <h2>{title}</h2>
            {children}
        </section>
    );
}
export function Pagination({
    offset,
    total,
    onChange,
    limit = 25,
}: {
    offset: number;
    total: number;
    onChange: (n: number) => void;
    limit?: number;
}) {
    useLocale();
    return (
        <nav className="pagination" aria-label={t("Seitennavigation")}>
            <button
                disabled={offset === 0}
                onClick={() => onChange(Math.max(0, offset - limit))}
            >
                {t("Zurück")}
            </button>
            <span>
                {total === 0
                    ? t("Keine Einträge")
                    : t("{0}–{1} von {2}", [
                          offset + 1,
                          Math.min(offset + limit, total),
                          number(total),
                      ])}
            </span>
            <button
                disabled={offset + limit >= total}
                onClick={() => onChange(offset + limit)}
            >
                {t("Weiter")}
            </button>
        </nav>
    );
}
const fieldNames: Record<string, string> = localized({
    snapshot_id: "Inventar-Snapshot",
    captured_at: "Erfasst am",
    processed_at: "Verarbeitet am",
    latest_snapshot_id: "Letzter Erfassungsversuch",
    latest_captured_at: "Zeitpunkt letzter Versuch",
    collection_status: "Erfassungsstatus letzter Versuch",
    processing_status: "Verarbeitungsstatus letzter Versuch",
    processing_error_code: "Fehler letzter Versuch",
    os_name: "Betriebssystem",
    os_version: "Betriebssystemversion",
    distribution: "Distribution",
    release: "Release",
    architecture: "Architektur",
    kernel_version: "Kernel",
    package_count: "Pakete",
    service_count: "Dienste",
    container_count: "Container",
    image_count: "Images",
    sections: "Abschnitte des gültigen Snapshots",
    package_managers: "Paketmanager",
    inventory_freshness: "Inventaraktualität",
    inventory_max_age_hours: "Konfigurierte Altersgrenze (Stunden)",
    last_matched_at: "Letzte Auswertung",
    evaluations: "Auswertungen",
    current_evaluations: "Aktuelle Auswertungen",
    finding_id: "Finding",
    rule_version: "Matching-Regel",
    enrichment_revision_id: "Enrichment-Revision",
    matched_at: "Ausgewertet am",
    coverage: "Abdeckung",
    data_quality: "Datenqualität",
    installed_version: "Installierte Version",
    fixed_version: "Fixversion laut Quelle",
    component_id: "Komponente",
    context: "Installationskontext",
    package_id: "Paketreferenz",
    decision: "Entscheidung",
    reason: "Begründung",
    status: "Status",
    version: "Version",
    score: "Wert",
    cvss_version: "CVSS-Version",
    base_score: "Basiswert",
    vector_string: "Vektor",
    score_date: "Datenstand",
    is_stale: "Veraltet",
    age_days: "Alter (Tage)",
    model_version: "Modellversion",
    dataset_id: "Quelldatensatz",
    percentile: "Perzentil",
    vector: "Vektor",
    source: "Quelle",
    created_at: "Erstellt am",
    occurred_at: "Zeitpunkt",
    kind: "Ereignis",
    old_value: "Vorher",
    new_value: "Nachher",
    actor_user_id: "Benutzer",
    actor_role: "Identität",
    number: "Episode",
    name: "Name",
    is_current: "Quellenstand aktuell",
    validation_status: "Validierungsstatus",
    date: "Datenstand",
    probability: "Wahrscheinlichkeit",
});
function Value({
    value,
    depth = 0,
}: {
    value: unknown;
    depth?: number;
}): ReactNode {
    useLocale();
    if (value === null || value === undefined) return t("Unbekannt");
    if (typeof value === "boolean") return value ? t("Ja") : t("Nein");
    if (typeof value === "object") {
        if (depth > 5) return t("Weitere Quelldetails vorhanden");
        return Array.isArray(value) ? (
            <ul>
                {value.map((v, i) => (
                    <li key={i}>
                        <Value value={v} depth={depth + 1} />
                    </li>
                ))}
            </ul>
        ) : (
            <dl className="facts">
                {Object.entries(value).map(([k, v]) => (
                    <div key={k}>
                        <dt>{t(fieldNames[k] ?? k)}</dt>
                        <dd>
                            <Value value={v} depth={depth + 1} />
                        </dd>
                    </div>
                ))}
            </dl>
        );
    }
    if (typeof value === "string") {
        if (
            /^\d{4}-\d{2}-\d{2}T/.test(value) &&
            Number.isFinite(Date.parse(value))
        )
            return date(value);
        const link = safeLink(value);
        if (link)
            return (
                <a href={link} target="_blank" rel="noopener noreferrer">
                    {value}
                </a>
            );
        return labels[value] ?? value;
    }
    return String(value);
}
export function Facts({ values }: { values: Record<string, unknown> }) {
    useLocale();
    return (
        <dl className="facts">
            {Object.entries(values).map(([key, value]) => (
                <div key={key}>
                    <dt>{t(fieldNames[key] ?? key)}</dt>
                    <dd>
                        {key === "actor_user_id" &&
                        typeof value === "string" ? (
                            value
                        ) : (
                            <Value value={value} />
                        )}
                    </dd>
                </div>
            ))}
        </dl>
    );
}
export function Distribution({
    title,
    values,
}: {
    title: string;
    values: Record<string, number>;
}) {
    useLocale();
    const max = Math.max(1, ...Object.values(values));
    return (
        <Card title={title}>
            {Object.keys(values).length === 0 ? (
                <p>{t("Keine Daten im berechtigten Bereich.")}</p>
            ) : (
                <table className="distribution">
                    <caption className="sr-only">{title}</caption>
                    <tbody>
                        {Object.entries(values).map(([key, value]) => (
                            <tr key={key}>
                                <th scope="row">{labels[key] ?? key}</th>
                                <td>
                                    <svg
                                        viewBox="0 0 200 12"
                                        aria-hidden="true"
                                    >
                                        <rect
                                            width={200}
                                            height={12}
                                            fill="#edf1f5"
                                        />
                                        <rect
                                            width={(value / max) * 200}
                                            height={12}
                                            fill="#087d8a"
                                        />
                                    </svg>
                                </td>
                                <td>{number(value)}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </Card>
    );
}
export function FindingRows({
    items,
}: {
    items: {
        affected_software?: Finding["affected_software"];
        id: string;
        cve_id: string;
        server_id: string;
        server_name?: string;
        current_priority: string;
        latest_matching_status: string;
        lifecycle_status: string;
        due_at: string | null;
        is_overdue: boolean;
        cvss?: Record<string, unknown> | null;
        epss?: Record<string, unknown> | null;
        kev_status?: string;
        kev_is_current?: boolean;
        first_detected_at?: string;
        assignee_user_id?: string | null;
    }[];
}) {
    useLocale();
    return (
        <div className="table-scroll">
            <table>
                <caption className="sr-only">
                    {t("Findings im berechtigten Bereich")}
                </caption>
                <thead>
                    <tr>
                        <th>{t("CVE / Finding")}</th>
                        <th>{t("Software / Bereich")}</th>
                        <th>{t("Server")}</th>
                        <th>{t("Bedrohung")}</th>
                        <th>{t("Technischer Status")}</th>
                        <th>{t("Lebenszyklus")}</th>
                        <th>{t("Risikodaten")}</th>
                        <th>{t("Erkannt / Zuständigkeit")}</th>
                        <th>{t("Frist")}</th>
                    </tr>
                </thead>
                <tbody>
                    {items.map((f) => (
                        <tr key={f.id}>
                            <td>
                                <Link to={`/findings/${f.id}`}>{f.cve_id}</Link>
                            </td>
                            <td>
                                <AffectedSoftware
                                    items={f.affected_software}
                                    compact
                                />
                            </td>
                            <td>
                                <Link to={`/servers/${f.server_id}`}>
                                    {f.server_name ?? f.server_id}
                                </Link>
                            </td>
                            <td>
                                <Threat finding={f} />
                            </td>
                            <td>
                                <Badge value={f.latest_matching_status} />
                            </td>
                            <td>
                                <Badge value={f.lifecycle_status} />
                            </td>
                            <td>
                                {t("CVSS")}{" "}
                                {String(
                                    f.cvss?.cvss_version ??
                                        f.cvss?.version ??
                                        "–",
                                )}
                                :{" "}
                                {String(
                                    f.cvss?.base_score ??
                                        f.cvss?.calculated_score ??
                                        f.cvss?.score ??
                                        t("Unbekannt"),
                                )}
                                <small>
                                    {t("KEV:")} {f.kev_status ?? t("Unbekannt")}{" "}
                                    ·{" "}
                                    {f.kev_is_current
                                        ? "aktuell"
                                        : t("nicht aktuell")}
                                </small>
                                <small>
                                    {t("EPSS:")} {percent(f.epss?.score)} ·{" "}
                                    {String(
                                        f.epss?.score_date ??
                                            f.epss?.date ??
                                            t("Datenstand unbekannt"),
                                    )}
                                    {f.epss?.is_stale ? t(" · veraltet") : ""}
                                </small>
                            </td>
                            <td>
                                {date(f.first_detected_at)}
                                <small>
                                    {f.assignee_user_id ??
                                        t("Nicht zugewiesen")}
                                </small>
                            </td>
                            <td>
                                {date(f.due_at)}
                                {f.is_overdue && (
                                    <strong> {t("· Überfällig")}</strong>
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
            {items.length === 0 && (
                <p className="empty">
                    {t("Keine Findings für diese Auswahl.")}
                </p>
            )}
        </div>
    );
}
