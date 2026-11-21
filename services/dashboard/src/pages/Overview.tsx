import { t, useLocale } from "../i18n";
import CveDataStatus from "./CveDataStatus";
import WorkflowControl from "./WorkflowControl";
import { useAuth } from "../auth";
import { useState } from "react";
import { overviewSchema, trendsSchema } from "../contracts";
import { useData, State, Card, Distribution } from "../ui";
import { number, date } from "../format";
export default function Overview() {
    useLocale();
    const { identity } = useAuth();
    if (!identity?.permissions.includes("security:overview:read"))
        return (
            <section role="alert">
                <h1>{t("Zugriff nicht erlaubt")}</h1>
            </section>
        );
    return (
        <OverviewContent
            administrative={identity.roles?.includes("admin") ?? false}
        />
    );
}
function OverviewContent({ administrative }: { administrative: boolean }) {
    useLocale();
    const [days, setDays] = useState(30);
    const overview = useData("/api/v1/dashboard/overview", overviewSchema);
    const trend = useData(
        `/api/v1/dashboard/overview/trends?days=${days}`,
        trendsSchema,
    );
    const d = overview.data;
    return (
        <>
            <header className="page-header">
                <div>
                    <p className="eyebrow">{t("CVE MONITORING")}</p>
                    <h1>
                        {administrative
                            ? t("Sicherheitsübersicht")
                            : t("Übersicht")}
                    </h1>
                    <p>{t("Aktueller Stand für Ihre berechtigten Server")}</p>
                </div>
                <button
                    onClick={() => {
                        overview.reload();
                        trend.reload();
                    }}
                >
                    {t("Ansicht neu laden")}
                </button>
            </header>
            {administrative && (
                <>
                    <CveDataStatus />
                    <WorkflowControl />
                </>
            )}
            {!d ? (
                <State error={overview.error} reload={overview.reload} />
            ) : (
                <>
                    <p className="muted">
                        {t("Stand")} {date(d.generated_at)}{" "}
                        {t(
                            "· Kennzahlen berücksichtigen Ihre Objektberechtigungen.",
                        )}
                    </p>
                    <div className="kpis">
                        {[
                            [t("Aktive Server"), d.active_servers],
                            [t("Offene Findings"), d.open_findings],
                            [t("Betroffene Server"), d.servers_affected],
                            [t("Überfällige Findings"), d.overdue],
                        ].map(([title, value]) => (
                            <section className="kpi" key={title}>
                                <h2>{title}</h2>
                                <strong>{number(value)}</strong>
                            </section>
                        ))}
                    </div>
                    <div className="notice">
                        {t("Kritisch:")} {number(d.critical)} {t("· Hoch:")}{" "}
                        {number(d.high)} {t("· Betroffen:")}{" "}
                        {number(
                            (d.technical.affected ?? 0) +
                                (d.technical.potentially_affected ?? 0),
                        )}{" "}
                        {t("· Nicht bewertbar:")} {number(d.unknown)}{" "}
                        {t("· Aktuelle KEV:")} {number(d.kev)}
                    </div>
                    <div className="grid-two">
                        <Distribution
                            title={t("Prioritäten")}
                            values={d.priorities}
                        />
                        <Distribution
                            title={t("Lebenszyklus")}
                            values={d.lifecycle}
                        />
                        <Distribution
                            title={t("Technische Bewertung")}
                            values={{
                                ...Object.fromEntries(
                                    Object.entries(d.technical).filter(
                                        ([key]) =>
                                            key !== "potentially_affected",
                                    ),
                                ),
                                affected:
                                    (d.technical.affected ?? 0) +
                                    (d.technical.potentially_affected ?? 0),
                            }}
                        />
                        <Distribution
                            title={t("Aktuelle KEV nach Priorität")}
                            values={d.kev_priorities}
                        />
                    </div>
                    <div className="grid-two">
                        <Card title={t("Inventarqualität")}>
                            {d.inventory_data_available ? (
                                <dl className="facts">
                                    {Object.entries(d.inventory).map(
                                        ([k, v]) => (
                                            <div key={k}>
                                                <dt>
                                                    {{
                                                        missing:
                                                            t("Inventar fehlt"),
                                                        stale: t(
                                                            "Inventar veraltet",
                                                        ),
                                                        incomplete: t(
                                                            "Letzter Versuch unvollständig",
                                                        ),
                                                        not_configured: t(
                                                            "Altersrichtlinie nicht konfiguriert",
                                                        ),
                                                    }[k] ?? k}
                                                </dt>
                                                <dd>{number(v)}</dd>
                                            </div>
                                        ),
                                    )}
                                </dl>
                            ) : (
                                <p>
                                    {t(
                                        "Keine Berechtigung zum Lesen des Inventars.",
                                    )}
                                </p>
                            )}
                        </Card>
                        <Distribution
                            title={t("Matching-Abdeckung")}
                            values={d.matching}
                        />
                    </div>
                </>
            )}
            <Card title={t("Finding-Verlauf")}>
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
                {!trend.data ? (
                    <State error={trend.error} reload={trend.reload} />
                ) : (
                    <>
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
                        <div
                            className="legend"
                            aria-label={t("Verlaufslegende")}
                        >
                            <span className="detected">
                                {t("Erstmals erkannt")}
                            </span>
                            <span className="resolved">{t("Behoben")}</span>
                            <span className="reopened">
                                {t("Wiedereröffnet")}
                            </span>
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
                            <summary>
                                {t("Verlauf als Tabelle anzeigen")}
                            </summary>
                            <div className="table-scroll">
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
        </>
    );
}
