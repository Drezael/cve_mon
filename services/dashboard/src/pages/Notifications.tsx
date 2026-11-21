import { t, useLocale } from "../i18n";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { notificationSchema, page, related } from "../contracts";
import { useData, State, Card, Facts, Badge, Pagination } from "../ui";
import { date, label } from "../format";
const schema = page(notificationSchema);
export default function Notifications() {
    useLocale();
    const [offset, setOffset] = useState(0);
    const [status, setStatus] = useState("");
    const r = useData(
        `/api/v1/dashboard/notifications?limit=25&offset=${offset}${status ? `&status=${status}` : ""}`,
        schema,
    );
    return (
        <>
            <h1>{t("Benachrichtigungen")}</h1>
            <p>
                {t(
                    "Nur Ihre gemäß aktuellen Berechtigungen sichtbaren Benachrichtigungen. Die Annahme durch Relay oder Smarthost beweist keine Zustellung.",
                )}
            </p>
            <label>
                {t("Status")}
                <select
                    value={status}
                    onChange={(e) => {
                        setStatus(e.target.value);
                        setOffset(0);
                    }}
                >
                    <option value="">{t("Alle")}</option>
                    {[
                        "planned",
                        "relay_accepted",
                        "upstream_accepted",
                        "delivery_confirmed",
                        "submission_uncertain",
                        "suppressed",
                        "permanent_failure",
                        "deferred",
                        "ready",
                        "leased",
                        "submitting",
                        "retryable_failure",
                        "bounced",
                        "cancelled",
                    ].map((v) => (
                        <option value={v} key={v}>
                            {label(v)}
                        </option>
                    ))}
                </select>
            </label>
            {!r.data ? (
                <State error={r.error} reload={r.reload} />
            ) : (
                <Card title={t("Versandverlauf")}>
                    <div className="table-scroll">
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("Zeitpunkt")}</th>
                                    <th>{t("Benachrichtigung")}</th>
                                    <th>{t("CVE / Finding")}</th>
                                    <th>{t("Server")}</th>
                                    <th>{t("Aktuelle Priorität")}</th>
                                    <th>{t("Status")}</th>
                                    <th>{t("Anlass")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {r.data.items.map((n) => (
                                    <tr key={n.id}>
                                        <td>{date(n.created_at)}</td>
                                        <td>
                                            <Link to={`/notifications/${n.id}`}>
                                                {label(n.kind)}
                                            </Link>
                                        </td>
                                        <td>
                                            {n.finding_id ? (
                                                <Link
                                                    to={`/findings/${n.finding_id}`}
                                                >
                                                    {n.cve_id ??
                                                        t("Finding öffnen")}
                                                </Link>
                                            ) : (
                                                t("Sammelbenachrichtigung")
                                            )}
                                        </td>
                                        <td>
                                            {n.server_id ? (
                                                <Link
                                                    to={`/servers/${n.server_id}`}
                                                >
                                                    {n.server_name ??
                                                        n.server_id}
                                                </Link>
                                            ) : (
                                                t("Mehrere Server")
                                            )}
                                        </td>
                                        <td>
                                            {n.current_priority ? (
                                                <Badge
                                                    value={n.current_priority}
                                                />
                                            ) : (
                                                <span>
                                                    {t("Nicht zutreffend")}
                                                </span>
                                            )}
                                        </td>
                                        <td>
                                            <Badge value={n.status} />
                                        </td>
                                        <td>{n.reason}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {r.data.total === 0 && (
                        <p>{t("Keine sichtbaren Benachrichtigungen.")}</p>
                    )}
                    <Pagination
                        offset={offset}
                        total={r.data.total}
                        onChange={setOffset}
                    />
                </Card>
            )}
        </>
    );
}
function Events({ id, kind }: { id: string; kind: string }) {
    useLocale();
    const [offset, setOffset] = useState(0);
    const r = useData(
        `/api/v1/dashboard/notifications/${id}/${kind}?limit=25&offset=${offset}`,
        related,
    );
    return !r.data ? (
        <State error={r.error} reload={r.reload} />
    ) : (
        <>
            {r.data.items.map((v, i) => (
                <div className="record" key={i}>
                    <Facts values={v} />
                </div>
            ))}
            {r.data.items.length === 0 && <p>{t("Keine Einträge.")}</p>}
            <div className="pagination">
                <button
                    disabled={!offset}
                    onClick={() => setOffset(offset - 25)}
                >
                    {t("Zurück")}
                </button>
                <button
                    disabled={r.data.items.length < 25}
                    onClick={() => setOffset(offset + 25)}
                >
                    {t("Weiter")}
                </button>
            </div>
        </>
    );
}
export function NotificationDetail() {
    useLocale();
    const { id = "" } = useParams();
    const r = useData(
        `/api/v1/dashboard/notifications/${id}`,
        notificationSchema,
    );
    return (
        <>
            <h1>{t("Benachrichtigungsdetails")}</h1>
            {!r.data ? (
                <State error={r.error} reload={r.reload} />
            ) : (
                <>
                    <Card title={t("Status")}>
                        <Badge value={r.data.status} />
                        <p>
                            {t(
                                "Relay- und Upstream-Annahme sind von nachgewiesener Zustellung getrennt.",
                            )}
                        </p>
                        <Facts
                            values={{
                                Benachrichtigung: r.data.id,
                                Typ: r.data.kind,
                                Anlass: r.data.reason,
                                CVE: r.data.cve_id,
                                Server: r.data.server_name,
                                "Aktuelle Priorität": r.data.current_priority,
                                Erstellt: date(r.data.created_at),
                                "Nachricht-ID": r.data.message_id,
                            }}
                        />
                        {r.data.finding_id && (
                            <Link to={`/findings/${r.data.finding_id}`}>
                                {t("Finding öffnen")}
                            </Link>
                        )}
                    </Card>
                    <Card title={t("Statusverlauf")}>
                        <Events id={id} kind="history" />
                    </Card>
                    <Card title={t("Versuche")}>
                        <Events id={id} kind="attempts" />
                    </Card>
                </>
            )}
        </>
    );
}
