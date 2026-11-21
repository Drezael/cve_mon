import { t, localized, useLocale } from "../i18n";
import { useCallback, useEffect, useState } from "react";
import { z } from "zod";
import { api } from "../api";
import { useAuth } from "../auth";
import { Card, State } from "../ui";
import { date, number } from "../format";

export const workflowSchema = z.object({
    queue: z
        .object({
            pending: z.number(),
            processing: z.number(),
            failed: z.number(),
            completed: z.number(),
        })
        .optional(),
    queue_items: z
        .array(
            z.object({
                id: z.string(),
                sequence: z.number(),
                kind: z.string(),
                producer: z.string(),
                message_type: z.string(),
                state: z.string(),
                created_at: z.string(),
                execution_id: z.string().nullable(),
                error_code: z.string().nullable(),
            }),
        )
        .optional(),
    enabled: z.boolean(),
    auto_updates: z.boolean(),
    update_interval: z.number(),
    next_update_at: z.string(),
    can_manage: z.boolean(),
    stages: z.array(
        z.object({
            stage: z.string(),
            waiting: z.number(),
            queued: z.number(),
            running: z.number(),
            failed: z.number(),
            last_release: z.string().nullable(),
            last_execution: z
                .object({ id: z.string(), workflow: z.string() })
                .nullable()
                .optional(),
        }),
    ),
    runs: z.array(
        z.object({
            correlation_id: z.string().uuid(),
            created_at: z.string(),
            paused: z.boolean(),
            cancelled: z.boolean(),
            waiting: z.number(),
            queued: z.number(),
            running: z.number(),
            failed: z.number(),
            stages: z.array(z.string()),
            last_release: z.string().nullable(),
        }),
    ),
});
const labels: Record<string, string> = localized({
    import: "V5-Import",
    inventory: "Inventare",
    enrichment: "Aufbereitung",
    index: "Suchindex",
    matching: "Inventarabgleich",
    findings: "Findings",
    notifications: "Benachrichtigungen",
    status: "Systemprüfung",
});

export default function WorkflowControl() {
    useLocale();
    const { identity } = useAuth();
    return identity?.permissions.includes("role:assign:privileged") ? (
        <Panel key={identity.privateKey} />
    ) : null;
}
function Panel() {
    useLocale();
    const [data, setData] = useState<z.infer<typeof workflowSchema> | null>(
        null,
    );
    const [loadError, setLoadError] = useState<Error | null>(null);
    const [version, setVersion] = useState(0);
    const reload = useCallback(() => setVersion((v) => v + 1), []);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<Error | null>(null);
    useEffect(() => {
        const controller = new AbortController();
        let timer: ReturnType<typeof setTimeout>;
        async function load() {
            try {
                const snapshot = await api(
                    "/api/v1/dashboard/orchestration",
                    workflowSchema,
                    { signal: controller.signal },
                );
                if (!controller.signal.aborted) {
                    setData(snapshot);
                    setLoadError(null);
                }
            } catch (e) {
                if (!controller.signal.aborted)
                    setLoadError(
                        e instanceof Error
                            ? e
                            : new Error(t("Steuerung nicht erreichbar")),
                    );
            }
            if (!controller.signal.aborted)
                timer = setTimeout(() => {
                    void load();
                }, 10000);
        }
        void load();
        return () => {
            controller.abort();
            clearTimeout(timer);
        };
    }, [version]);
    async function command(
        path: string,
        method: "POST" | "PUT",
        body?: unknown,
    ) {
        setBusy(true);
        setError(null);
        try {
            await api(path, z.unknown(), { method, body });
            reload();
        } catch (e) {
            setError(
                e instanceof Error
                    ? e
                    : new Error(t("Der Ablauf konnte nicht geändert werden.")),
            );
        } finally {
            setBusy(false);
        }
    }
    return (
        <Card title={t("Zentrale Steuerung · n8n")}>
            {!data ? (
                <State error={loadError} reload={reload} />
            ) : (
                <>
                    <p>
                        {data.enabled
                            ? t(
                                  "n8n steuert die Verarbeitungsschritte aller Anwendungskomponenten.",
                              )
                            : t(
                                  "Die zentrale Steuerung ist noch nicht aktiviert.",
                              )}
                    </p>
                    <dl className="facts">
                        <div>
                            <dt>{t("Automatische V5-Updates")}</dt>
                            <dd>
                                {data.auto_updates
                                    ? t("Alle {0} Minuten", [
                                          data.update_interval / 60,
                                      ])
                                    : t("Pausiert")}
                            </dd>
                        </div>
                        <div>
                            <dt>{t("Nächste automatische Prüfung")}</dt>
                            <dd>
                                {data.enabled && data.auto_updates
                                    ? date(data.next_update_at)
                                    : t("Nicht eingeplant")}
                            </dd>
                        </div>
                        <div>
                            <dt>{t("Wartet auf n8n-Freigabe")}</dt>
                            <dd>
                                {number(
                                    data.stages.reduce(
                                        (n, s) => n + s.waiting,
                                        0,
                                    ),
                                )}
                            </dd>
                        </div>
                    </dl>
                    {data.queue && (
                        <section aria-label={t("n8n Job Queue")}>
                            <h3>{t("n8n Job Queue · FIFO")}</h3>
                            <p>
                                {number(data.queue.pending)} {t("wartend ·")}{" "}
                                {number(data.queue.processing)}{" "}
                                {t("in Übernahme ·")}{" "}
                                {number(data.queue.failed)}{" "}
                                {t("fehlgeschlagen ·")}{" "}
                                {number(data.queue.completed)} {t("übernommen")}
                            </p>
                            {!!data.queue_items?.length && (
                                <div className="table-scroll">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>{t("Reihenfolge")}</th>
                                                <th>{t("Komponente")}</th>
                                                <th>{t("Nachricht")}</th>
                                                <th>{t("Status")}</th>
                                                <th>{t("n8n-Ausführung")}</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {data.queue_items.map((item) => (
                                                <tr key={item.id}>
                                                    <td>{item.sequence}</td>
                                                    <td>{item.producer}</td>
                                                    <td>
                                                        {item.kind}:{" "}
                                                        {item.message_type}
                                                    </td>
                                                    <td>{item.state}</td>
                                                    <td>
                                                        {item.execution_id ??
                                                            "—"}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </section>
                    )}
                    {data.can_manage && (
                        <form
                            key={`${data.auto_updates}:${data.update_interval}`}
                            className="filters"
                            onSubmit={(e) => {
                                e.preventDefault();
                                const fields = new FormData(e.currentTarget);
                                void command(
                                    "/api/v1/dashboard/orchestration/settings",
                                    "PUT",
                                    {
                                        auto_updates:
                                            fields.get("automatic") === "on",
                                        update_interval: Number(
                                            fields.get("interval"),
                                        ),
                                    },
                                );
                            }}
                        >
                            <label>
                                <input
                                    type="checkbox"
                                    name="automatic"
                                    defaultChecked={data.auto_updates}
                                    disabled={busy || !data.enabled}
                                />{" "}
                                {t("Automatische Updates aktivieren")}
                            </label>
                            <label>
                                {t("Prüfintervall")}
                                <select
                                    name="interval"
                                    defaultValue={String(data.update_interval)}
                                    disabled={busy || !data.enabled}
                                >
                                    {Array.from(
                                        new Set([
                                            300,
                                            900,
                                            1800,
                                            3600,
                                            7200,
                                            86400,
                                            data.update_interval,
                                        ]),
                                    )
                                        .sort((a, b) => a - b)
                                        .map((v) => (
                                            <option key={v} value={v}>
                                                {v / 60} {t("Minuten")}
                                            </option>
                                        ))}
                                </select>
                            </label>
                            <button
                                type="submit"
                                disabled={busy || !data.enabled}
                            >
                                {t("Zeitplan speichern")}
                            </button>
                        </form>
                    )}
                    <details>
                        <summary>
                            {t("Verarbeitungsschritte und Abläufe anzeigen")}
                        </summary>
                        <div className="table-scroll">
                            <table>
                                <thead>
                                    <tr>
                                        <th>{t("Verarbeitungsschritt")}</th>
                                        <th>{t("Wartet auf n8n")}</th>
                                        <th>{t("Eingereiht")}</th>
                                        <th>{t("Läuft")}</th>
                                        <th>
                                            {t("Fehlgeschlagen (24 Stunden)")}
                                        </th>
                                        <th>{t("Letzte Freigabe")}</th>
                                        <th>{t("n8n-Ausführung")}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {data.stages.map((s) => (
                                        <tr key={s.stage}>
                                            <th scope="row">
                                                {labels[s.stage] ?? s.stage}
                                            </th>
                                            <td>{number(s.waiting)}</td>
                                            <td>{number(s.queued)}</td>
                                            <td>{number(s.running)}</td>
                                            <td>{number(s.failed)}</td>
                                            <td>
                                                {s.last_release
                                                    ? date(s.last_release)
                                                    : t("Noch keine")}
                                            </td>
                                            <td>
                                                {s.last_execution ? (
                                                    <code
                                                        title={
                                                            s.last_execution
                                                                .workflow
                                                        }
                                                    >
                                                        {s.last_execution.id}
                                                    </code>
                                                ) : (
                                                    t("Noch keine")
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                        <p className="muted">
                            {t(
                                "Eine Pause verhindert neue Schritte. Laufende Aufträge dürfen abschließen. Abbrechen beendet ausstehende Arbeit; gespeicherte CVEs und Inventare bleiben erhalten.",
                            )}
                        </p>
                        <h3>{t("Letzte Abläufe")}</h3>
                        {data.runs.length === 0 ? (
                            <p>{t("Noch keine gesteuerten Abläufe.")}</p>
                        ) : (
                            <div className="table-scroll">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>{t("Ablauf")}</th>
                                            <th>{t("Schritte")}</th>
                                            <th>{t("Stand")}</th>
                                            <th>{t("Aktionen")}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {data.runs.map((r) => (
                                            <tr key={r.correlation_id}>
                                                <th scope="row">
                                                    <code
                                                        title={r.correlation_id}
                                                    >
                                                        {r.correlation_id.slice(
                                                            0,
                                                            8,
                                                        )}
                                                    </code>
                                                    <br />
                                                    {date(r.created_at)}
                                                </th>
                                                <td>
                                                    {r.stages
                                                        .map(
                                                            (s) =>
                                                                labels[s] ?? s,
                                                        )
                                                        .join(", ")}
                                                </td>
                                                <td>
                                                    {r.cancelled
                                                        ? t("Abgebrochen")
                                                        : r.paused
                                                          ? t("Pausiert")
                                                          : r.running
                                                            ? t("Läuft")
                                                            : r.waiting
                                                              ? t(
                                                                    "Wartet auf n8n",
                                                                )
                                                              : r.queued
                                                                ? t(
                                                                      "Eingereiht",
                                                                  )
                                                                : r.failed
                                                                  ? t(
                                                                        "Fehlgeschlagen",
                                                                    )
                                                                  : t(
                                                                        "Abgeschlossen",
                                                                    )}
                                                </td>
                                                <td>
                                                    {data.can_manage &&
                                                        !r.cancelled &&
                                                        r.waiting +
                                                            r.running +
                                                            r.queued >
                                                            0 && (
                                                            <>
                                                                <button
                                                                    disabled={
                                                                        busy
                                                                    }
                                                                    onClick={() =>
                                                                        void command(
                                                                            `/api/v1/dashboard/orchestration/runs/${r.correlation_id}/${r.paused ? "resume" : "pause"}`,
                                                                            "POST",
                                                                            {},
                                                                        )
                                                                    }
                                                                >
                                                                    {r.paused
                                                                        ? t(
                                                                              "Fortsetzen",
                                                                          )
                                                                        : t(
                                                                              "Pause",
                                                                          )}
                                                                </button>{" "}
                                                                <button
                                                                    disabled={
                                                                        busy
                                                                    }
                                                                    onClick={() =>
                                                                        void command(
                                                                            `/api/v1/dashboard/orchestration/runs/${r.correlation_id}/cancel`,
                                                                            "POST",
                                                                            {},
                                                                        )
                                                                    }
                                                                >
                                                                    {t(
                                                                        "Abbrechen",
                                                                    )}
                                                                </button>
                                                            </>
                                                        )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </details>
                </>
            )}
            {(error || (data && loadError)) && (
                <State
                    error={error ?? loadError}
                    reload={() => {
                        setError(null);
                        reload();
                    }}
                />
            )}
        </Card>
    );
}
