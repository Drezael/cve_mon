import { translateMessage, t, localized, useLocale } from "../i18n";
import { useEffect, useRef, useState } from "react";
import { z } from "zod";
import { api } from "../api";
import { useAuth } from "../auth";
import { date, number } from "../format";
import { Card, State } from "../ui";

export const dataStatusSchema = z.object({
    cve_count: z.number().int().nonnegative(),
    record_count: z.number().int().nonnegative(),
    last_success_at: z.string().nullable(),
    updating: z.boolean(),
    can_update: z.boolean(),
    queue: z
        .object({
            pending: z.number(),
            processing: z.number(),
            failed: z.number(),
            position: z.number().nullable(),
            id: z.string().nullable(),
            state: z.string().nullable(),
        })
        .nullable()
        .optional(),
    pipeline: z.object({
        indexed_records: z.number().int().nonnegative().default(0),
        processed_records: z.number().int().nonnegative(),
        processed_cves: z.number().int().nonnegative(),
        processed_advisories: z.number().int().nonnegative(),
        waiting: z.number().int().nonnegative(),
        retrying: z.number().int().nonnegative(),
        running: z.number().int().nonnegative(),
        outstanding: z.number().int().nonnegative(),
        completed_jobs: z.number().int().nonnegative(),
        failed_jobs: z.number().int().nonnegative(),
    }),
    sources: z.array(
        z.object({
            git_commit: z.string().nullable().optional(),
            error_count: z.number().int().nonnegative().default(0),
            id: z.string(),
            name: z.string(),
            record_count: z.number(),
            last_success_at: z.string().nullable(),
            last_attempt_at: z.string().nullable(),
            status: z.string(),
            enabled: z.boolean(),
            configured: z.boolean(),
            updating: z.boolean(),
        }),
    ),
});
const updateSchema = z.object({
    jobs: z.array(z.object({ source: z.string(), id: z.uuid() })),
});
const statuses: Record<string, string> = localized({
    never: "Noch nie aktualisiert",
    planned: "Eingeplant",
    pending: "Eingeplant",
    queued: "Eingeplant",
    running: "Wird aktualisiert",
    retry_pending: "Erneuter Versuch ausstehend",
    completed: "Erfolgreich",
    partial: "Unvollständig",
    failed: "Fehlgeschlagen",
    cancelled: "Abgebrochen",
    timed_out: "Zeitüberschreitung",
});
export default function CveDataStatus() {
    useLocale();
    const { identity } = useAuth();
    return identity?.permissions.includes("cve:read") ? (
        <DataPanel key={identity.privateKey} />
    ) : null;
}
function DataPanel() {
    useLocale();
    const [data, setData] = useState<z.infer<typeof dataStatusSchema> | null>(
        null,
    );
    const [error, setError] = useState<Error | null>(null);
    const [busy, setBusy] = useState(false);
    const [message, setMessage] = useState("");
    const [version, setVersion] = useState(0);
    const requestKey = useRef<string | null>(null);
    const active = useRef<AbortController | null>(null);
    const locked = useRef(false);
    useEffect(() => {
        const c = new AbortController();
        let timer: ReturnType<typeof setTimeout>;
        async function load() {
            try {
                const value = await api(
                    "/api/v1/dashboard/cve-data",
                    dataStatusSchema,
                    { signal: c.signal },
                );
                if (c.signal.aborted) return;
                setData(value);
                setError(null);
                timer = setTimeout(
                    () => {
                        void load();
                    },
                    value.updating || value.pipeline.outstanding > 0
                        ? 5000
                        : 30000,
                );
            } catch (e) {
                if (!c.signal.aborted) {
                    setError(
                        e instanceof Error
                            ? e
                            : new Error(
                                  t("Daten konnten nicht geladen werden."),
                              ),
                    );
                    timer = setTimeout(() => {
                        void load();
                    }, 30000);
                }
            }
        }
        void load();
        return () => {
            c.abort();
            clearTimeout(timer);
        };
    }, [version]);
    useEffect(() => () => active.current?.abort(), []);
    async function refresh() {
        if (locked.current) return;
        locked.current = true;
        setBusy(true);
        setMessage("");
        setError(null);
        const c = new AbortController();
        active.current = c;
        requestKey.current ??= crypto.randomUUID();
        try {
            const result = await api(
                "/api/v1/dashboard/cve-data/refresh",
                updateSchema,
                {
                    method: "POST",
                    idempotencyKey: requestKey.current,
                    signal: c.signal,
                },
            );
            if (!c.signal.aborted) {
                requestKey.current = null;
                setMessage(
                    t(
                        "Auftrag in die n8n-Queue eingereiht ({0}). n8n übernimmt ihn der Reihe nach.",
                        [result.jobs.length],
                    ),
                );
                setVersion((v) => v + 1);
            }
        } catch (e) {
            if (!c.signal.aborted)
                setError(
                    e instanceof Error
                        ? e
                        : new Error(
                              t(
                                  "Aktualisierung konnte nicht gestartet werden.",
                              ),
                          ),
                );
        } finally {
            locked.current = false;
            if (!c.signal.aborted) setBusy(false);
        }
    }
    return (
        <Card title={t("CVE-Datenbank")}>
            {!data ? (
                <State error={error} reload={() => setVersion((v) => v + 1)} />
            ) : (
                <>
                    <div className="pipeline-kpis">
                        <section className="kpi">
                            <h3>{t("Heruntergeladen / eingelesen")}</h3>
                            <strong>{number(data.record_count)}</strong>
                            <p>{t("Validierte V5-Dokumente")}</p>
                        </section>
                        <section className="kpi">
                            <h3>{t("Gespeichert")}</h3>
                            <strong>
                                {number(data.pipeline.processed_records)}
                            </strong>
                            <p>
                                {number(data.pipeline.processed_cves)}{" "}
                                {t("CVEs ·")}{" "}
                                {number(data.pipeline.processed_advisories)}{" "}
                                {t("Advisories")}
                            </p>
                        </section>
                        <section className="kpi">
                            <h3>{t("Noch in der Pipeline")}</h3>
                            <strong>{number(data.pipeline.outstanding)}</strong>
                            <p>{t("Offene Verarbeitungspakete")}</p>
                        </section>
                    </div>
                    <dl className="facts">
                        <div>
                            <dt>{t("Für den Inventarabgleich indiziert")}</dt>
                            <dd>{number(data.pipeline.indexed_records)}</dd>
                        </div>
                        <div>
                            <dt>{t("Wartend")}</dt>
                            <dd>{number(data.pipeline.waiting)}</dd>
                        </div>
                        <div>
                            <dt>{t("In Verarbeitung")}</dt>
                            <dd>{number(data.pipeline.running)}</dd>
                        </div>
                        <div>
                            <dt>{t("Erneuter Versuch ausstehend")}</dt>
                            <dd>{number(data.pipeline.retrying)}</dd>
                        </div>
                        <div>
                            <dt>{t("Abgeschlossene Aufträge (Historie)")}</dt>
                            <dd>{number(data.pipeline.completed_jobs)}</dd>
                        </div>
                        {data.pipeline.failed_jobs > 0 && (
                            <div>
                                <dt>
                                    {t("Fehlgeschlagene Aufträge (Historie)")}
                                </dt>
                                <dd>{number(data.pipeline.failed_jobs)}</dd>
                            </div>
                        )}
                        <div>
                            <dt>
                                {t(
                                    "Letzte erfolgreiche Aktualisierung einer Quelle",
                                )}
                            </dt>
                            <dd>
                                {data.last_success_at
                                    ? date(data.last_success_at)
                                    : t(
                                          "Noch keine erfolgreiche Aktualisierung",
                                      )}
                            </dd>
                        </div>
                    </dl>
                    {data.record_count === 0 && (
                        <p>{t("Noch keine CVE-Quelldaten importiert.")}</p>
                    )}
                    <p className="muted">
                        {t(
                            "Das vollständige V5-JSON wird direkt gespeichert. Anschließend werden nur die Suchschlüssel für den Inventarabgleich erzeugt. Die Pipeline zählt Pakete, die mehrere CVEs enthalten können.",
                        )}
                    </p>
                    {data.pipeline.outstanding > 0 && (
                        <p role="status">
                            {t(
                                "Die Verarbeitung ist noch nicht abgeschlossen. Diese Zahlen werden alle fünf Sekunden aktualisiert.",
                            )}
                        </p>
                    )}
                    <p className="muted">
                        {t(
                            "Der neueste erfolgreiche Import gilt jeweils für eine Quelle. Den Stand aller Quellen sehen Sie unten. Die Verarbeitung neuer Daten kann einige Zeit dauern.",
                        )}
                    </p>
                    <div className="table-scroll">
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("Quelle")}</th>
                                    <th>{t("Quelldatensätze")}</th>
                                    <th>{t("Letzter erfolgreicher Import")}</th>
                                    <th>{t("Letzter Versuch")}</th>
                                    <th>{t("Git-Stand")}</th>
                                    <th>{t("Fehler beim letzten Import")}</th>
                                    <th>{t("Status")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.sources.map((s) => (
                                    <tr key={s.id}>
                                        <th scope="row">{s.name}</th>
                                        <td>{number(s.record_count)}</td>
                                        <td>
                                            {s.last_success_at
                                                ? date(s.last_success_at)
                                                : t("Noch keiner")}
                                        </td>
                                        <td>
                                            {s.last_attempt_at
                                                ? date(s.last_attempt_at)
                                                : t("Noch keiner")}
                                        </td>
                                        <td>
                                            {s.git_commit ? (
                                                <code title={s.git_commit}>
                                                    {s.git_commit.slice(0, 12)}
                                                </code>
                                            ) : (
                                                t("Noch keiner")
                                            )}
                                        </td>
                                        <td>{number(s.error_count)}</td>
                                        <td>
                                            {s.updating
                                                ? [
                                                      "planned",
                                                      "pending",
                                                      "queued",
                                                      "running",
                                                      "retry_pending",
                                                  ].includes(s.status)
                                                    ? statuses[s.status]
                                                    : t("Wird aktualisiert")
                                                : !s.enabled
                                                  ? t("Deaktiviert")
                                                  : !s.configured
                                                    ? t("Nicht konfiguriert")
                                                    : (statuses[s.status] ??
                                                      t("Unbekannt"))}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {data.queue &&
                        (data.queue.pending > 0 ||
                            data.queue.processing > 0) && (
                            <p role="status">
                                {t("n8n-Queue:")} {data.queue.pending}{" "}
                                {t("Aktualisierungsaufträge warten.")}
                                {data.queue.position !== null &&
                                    t(" Nächster Auftrag: Position {0}.", [
                                        data.queue.position,
                                    ])}
                                {data.queue.processing > 0 &&
                                    t(" n8n übernimmt den Auftrag.")}
                            </p>
                        )}
                    {data.can_update && (
                        <button
                            disabled={
                                busy ||
                                data.updating ||
                                (error !== null && !requestKey.current)
                            }
                            onClick={() => {
                                void refresh();
                            }}
                        >
                            {busy
                                ? t("Wird eingereiht …")
                                : data.updating
                                  ? t("Aktualisierung läuft …")
                                  : t("Datenbank aktualisieren")}
                        </button>
                    )}
                    {data.updating && (
                        <p role="status">
                            {t(
                                "Die Aktualisierung läuft im Hintergrund. Diese Anzeige wird automatisch aktualisiert.",
                            )}
                        </p>
                    )}
                    {message && (
                        <p role="status">{translateMessage(message)}</p>
                    )}
                    {error && (
                        <State
                            error={error}
                            reload={() => setVersion((v) => v + 1)}
                        />
                    )}
                </>
            )}
        </Card>
    );
}
