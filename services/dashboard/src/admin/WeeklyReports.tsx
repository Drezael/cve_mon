import { translateMessage, intlLocale, t, localized, useLocale } from "../i18n";
import { useEffect, useRef, useState } from "react";
import { z } from "zod";
import { api } from "../api";
import { Card, State, useData } from "../ui";
import { date } from "../format";
const base = "/api/v1/dashboard/notifications/reports";
const config = z.object({
    enabled: z.boolean(),
    weekday: z.number(),
    time: z.string(),
    timezone: z.string(),
});
const schedule = z.object({
    version: z.number(),
    configuration: config,
    next_run_at: z.string().nullable(),
});
const history = z.object({
    items: z.array(
        z.object({
            id: z.string(),
            origin: z.string(),
            state: z.string(),
            created_at: z.string(),
            server_count: z.number(),
            delivery_status: z.string().nullable(),
            error_code: z.string().nullable(),
        }),
    ),
});
const receipt = z.object({ id: z.string(), state: z.string() });
const days = localized([
    "Montag",
    "Dienstag",
    "Mittwoch",
    "Donnerstag",
    "Freitag",
    "Samstag",
    "Sonntag",
]);
function scheduledDate(value: string, zone: string) {
    try {
        return new Intl.DateTimeFormat(intlLocale(), {
            dateStyle: "full",
            timeStyle: "short",
            timeZone: zone,
        }).format(new Date(value));
    } catch {
        return date(value);
    }
}
export default function WeeklyReports() {
    useLocale();
    const result = useData(base + "/schedule", schedule);
    const reports = useData(base, history, { refreshInterval: 10000 });
    const [draft, setDraft] = useState({
        enabled: true,
        weekday: 0,
        time: "09:00",
        timezone: "Europe/Berlin",
    });
    const [busy, setBusy] = useState(false);
    const [notice, setNotice] = useState("");
    const [error, setError] = useState("");
    const requestKey = useRef<string | null>(null);
    useEffect(() => {
        if (result.data) setDraft(result.data.configuration);
    }, [result.data]);
    async function save() {
        if (!result.data || busy) return;
        setBusy(true);
        setError("");
        try {
            await api(base + "/schedule", schedule, {
                method: "PUT",
                version: result.data.version,
                body: draft,
            });
            setNotice(t("Wochenbericht gespeichert."));
            result.reload();
        } catch (e) {
            setError(
                e instanceof Error ? e.message : t("Speichern fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    async function now() {
        if (busy) return;
        setBusy(true);
        setError("");
        requestKey.current ??= crypto.randomUUID();
        try {
            await api(base + "/request", receipt, {
                method: "POST",
                idempotencyKey: requestKey.current,
            });
            requestKey.current = null;
            setNotice(
                t(
                    "Bericht angefordert. Die Mail wird nach Abschluss aller Serverscans versendet.",
                ),
            );
            reports.reload();
        } catch (e) {
            setError(
                e instanceof Error
                    ? e.message
                    : t("Anforderung fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    return (
        <Card title={t("Wochenbericht")}>
            <p>
                {t(
                    "Eine gemeinsame Mail umfasst alle von dir verwalteten Server – auch Server ohne Findings. Vor dem Versand werden die vorhandenen Inventare erneut geprüft.",
                )}
            </p>
            <p>
                {t(
                    "Automatische Meldungen über neue Findings werden pro Server zusammengefasst und erst nach dem vollständigen Scan versendet.",
                )}
            </p>
            {notice && <p role="status">{translateMessage(notice)}</p>}
            {error && (
                <p role="alert">
                    {translateMessage(error)}{" "}
                    <button onClick={result.reload}>{t("Neu laden")}</button>
                </p>
            )}
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        void save();
                    }}
                >
                    <label>
                        <input
                            type="checkbox"
                            checked={draft.enabled}
                            disabled={busy}
                            onChange={(e) =>
                                setDraft({
                                    ...draft,
                                    enabled: e.target.checked,
                                })
                            }
                        />{" "}
                        {t("Wochenbericht automatisch versenden")}
                    </label>
                    <label>
                        {t("Wochentag")}
                        <select
                            aria-label={t("Wochentag")}
                            value={draft.weekday}
                            disabled={busy}
                            onChange={(e) =>
                                setDraft({
                                    ...draft,
                                    weekday: Number(e.target.value),
                                })
                            }
                        >
                            {days.map((v, i) => (
                                <option key={v} value={i}>
                                    {v}
                                </option>
                            ))}
                        </select>
                    </label>
                    <label>
                        {t("Uhrzeit")}
                        <input
                            type="time"
                            required
                            value={draft.time}
                            disabled={busy}
                            onChange={(e) =>
                                setDraft({ ...draft, time: e.target.value })
                            }
                        />
                    </label>
                    <label>
                        {t("Zeitzone")}
                        <input
                            required
                            maxLength={64}
                            value={draft.timezone}
                            disabled={busy}
                            onChange={(e) =>
                                setDraft({ ...draft, timezone: e.target.value })
                            }
                        />
                    </label>
                    <p>
                        {t("Nächster Wochenbericht:")}{" "}
                        {result.data.next_run_at
                            ? scheduledDate(
                                  result.data.next_run_at,
                                  result.data.configuration.timezone,
                              )
                            : `${days[draft.weekday]}, ${draft.time} (${draft.timezone})`}
                    </p>
                    <button type="submit" disabled={busy}>
                        {t("Wochenbericht speichern")}
                    </button>{" "}
                    <button
                        type="button"
                        disabled={busy}
                        onClick={() => void now()}
                    >
                        {t("Wochenbericht jetzt anfordern")}
                    </button>
                </form>
            )}
            {reports.data && reports.data.items.length > 0 && (
                <div className="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>{t("Angefordert")}</th>
                                <th>{t("Bericht")}</th>
                                <th>{t("Server")}</th>
                                <th>{t("Status")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {reports.data.items.map((r) => (
                                <tr key={r.id}>
                                    <td>{date(r.created_at)}</td>
                                    <td>
                                        {r.origin === "scan"
                                            ? t("Serverscan")
                                            : r.origin === "weekly"
                                              ? t("Wochenbericht")
                                              : t("Jetzt angefordert")}
                                    </td>
                                    <td>{r.server_count}</td>
                                    <td>
                                        {[
                                            "relay_accepted",
                                            "upstream_accepted",
                                            "delivery_confirmed",
                                        ].includes(r.delivery_status ?? "")
                                            ? t("Versendet")
                                            : r.state === "failed"
                                              ? t(
                                                    "Scan fehlgeschlagen – kein unvollständiger Bericht versendet",
                                                )
                                              : r.state === "cancelled"
                                                ? t("Abgebrochen")
                                                : r.delivery_status ===
                                                    "suppressed"
                                                  ? t(
                                                        "Nicht versendet – Präferenzen oder Zugriff prüfen",
                                                    )
                                                  : r.state === "requested"
                                                    ? t("In der Warteschlange")
                                                    : r.state === "scanning"
                                                      ? t("Serverscans laufen")
                                                      : t(
                                                            "Versand wird vorbereitet",
                                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </Card>
    );
}
