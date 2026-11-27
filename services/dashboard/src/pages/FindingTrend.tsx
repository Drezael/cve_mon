import { useState } from "react";
import { t, useLocale } from "../i18n";
import { useData, State, Card } from "../ui";
import { trendsSchema } from "../contracts";
import { ApiError } from "../api";
import { date } from "../format";
export default function FindingTrend({
    initialDays = 30,
    interval = 0,
    title,
}: {
    initialDays?: number;
    interval?: number;
    title?: string;
}) {
    useLocale();
    const [days, setDays] = useState(initialDays);
    const trend = useData(
        `/api/v1/dashboard/overview/trends?days=${days}`,
        trendsSchema,
        { refreshInterval: interval },
    );
    return (
        <Card title={title ?? t("Finding-Verlauf")}>
            <label>
                {t("Zeitraum")}{" "}
                <select
                    value={days}
                    onChange={(e) => setDays(Number(e.target.value))}
                >
                    <option value={7}>{t("7 Tage")}</option>
                    <option value={30}>{t("30 Tage")}</option>
                    <option value={90}>{t("90 Tage")}</option>
                </select>
            </label>
            <p className="muted">
                {t(
                    "Ereignisse je UTC-Kalendertag. Wiedereröffnung und erstmalige Erkennung werden getrennt gezählt.",
                )}
            </p>
            {!trend.data || (trend.error instanceof ApiError && [401,403,404].includes(trend.error.status)) ? (
                <State error={trend.error} reload={trend.reload} />
            ) : (
                <>
                    <p className="muted">{t("Stand")}: {date(trend.updatedAt)}</p>
                    {trend.error && <p role="status">{t("Aktualisierung fehlgeschlagen. Der letzte Stand bleibt sichtbar.")}</p>}
                    <button onClick={trend.reload}>{t("Aktualisieren")}</button>
                    <svg
                        className="trend"
                        viewBox="0 0 800 160"
                        role="img"
                        aria-label={t(
                            "Finding-Verlauf; vollständige Werte in der folgenden Tabelle",
                        )}
                    >
                        {(
                            [
                                "detected",
                                "resolved",
                                "reopened",
                                "closed",
                            ] as const
                        ).map((kind, index) => {
                            const items = trend.data!.items;
                            const max = Math.max(
                                1,
                                ...items.flatMap((i) => [
                                    i.detected,
                                    i.resolved,
                                    i.reopened,
                                    i.closed,
                                ]),
                            );
                            return (
                                <polyline
                                    key={kind}
                                    fill="none"
                                    stroke={
                                        [
                                            "#087d8a",
                                            "#287343",
                                            "#9d5200",
                                            "#6256a5",
                                        ][index]
                                    }
                                    strokeWidth="3"
                                    points={items
                                        .map(
                                            (item, i) =>
                                                `${10 + (i / Math.max(1, items.length - 1)) * 780},${150 - (item[kind] / max) * 140}`,
                                        )
                                        .join(" ")}
                                />
                            );
                        })}
                    </svg>
                    <div className="legend" aria-label={t("Verlaufslegende")}>
                        <span className="detected">
                            {t("Erstmals erkannt")}
                        </span>
                        <span className="resolved">{t("Behoben")}</span>
                        <span className="reopened">{t("Wiedereröffnet")}</span>
                        <span className="closed">{t("Geschlossen")}</span>
                    </div>
                    <p className="muted">
                        {trend.data.items[0]?.day} {t("bis")}{" "}
                        {trend.data.items.at(-1)?.day}{" "}
                        {t("(UTC) · gemeinsame Skala ab 0 bis")}{" "}
                        {Math.max(
                            1,
                            ...trend.data.items.flatMap((i) => [
                                i.detected,
                                i.resolved,
                                i.reopened,
                                i.closed,
                            ]),
                        )}{" "}
                        {t("Ereignisse pro Tag")}
                    </p>
                    <details>
                        <summary>{t("Verlauf als Tabelle anzeigen")}</summary>
                        <div
                            className="table-scroll"
                            tabIndex={0}
                            role="region"
                            aria-label={t("Scrollbare Tabelle")}
                        >
                            <table>
                                <thead>
                                    <tr>
                                        <th>{t("Datum (UTC)")}</th>
                                        <th>{t("Erstmals erkannt")}</th>
                                        <th>{t("Behoben")}</th>
                                        <th>{t("Wiedereröffnet")}</th>
                                        <th>{t("Geschlossen")}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {trend.data.items.map((i) => (
                                        <tr key={i.day}>
                                            <th scope="row">{i.day}</th>
                                            <td>{i.detected}</td>
                                            <td>{i.resolved}</td>
                                            <td>{i.reopened}</td>
                                            <td>{i.closed}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </details>
                </>
            )}
        </Card>
    );
}
