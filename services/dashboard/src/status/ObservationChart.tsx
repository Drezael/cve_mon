import { useState, useId } from "react";
import { t, useLocale } from "../i18n";
import type { Row } from "../admin/contracts";
import { labels, time } from "./presentation";

export function ObservationChart({ samples }: { samples: Row[] }) {
    useLocale();
    const title = useId();
    const metricTitle = useId();
    const [metric, setMetric] = useState("duration_ms");
    const points = samples.slice(-100);
    const values = points.map((s) => Date.parse(String(s.checked_at)));
    const metricKeys = [
        ...new Set([
            "duration_ms",
            ...points.flatMap((p) => Object.keys((p.metrics as Row) ?? {})),
        ]),
    ];
    const numeric = points.map((p) =>
        metric === "duration_ms"
            ? p.duration_ms
            : ((p.metrics as Row) ?? {})[metric],
    );
    const maxMetric = Math.max(
        1,
        ...numeric.filter((v): v is number => typeof v === "number"),
    );
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = Math.max(1, max - min);
    return (
        <>
            {points.length ? (
                <svg
                    role="img"
                    aria-labelledby={title}
                    viewBox="0 0 700 90"
                    className="status-chart"
                >
                    <title id={title}>
                        {t(
                            "Gemessene Statuspunkte, ohne Interpolation. Details in der folgenden Tabelle.",
                        )}
                    </title>
                    {points.map((p, i) => (
                        <rect
                            key={i}
                            x={8 + ((values[i] - min) / span) * 680}
                            y={20}
                            width={6}
                            height={40}
                            className={"point-" + String(p.result)}
                        >
                            <title>
                                {time(p.checked_at)}: {labels[String(p.result)]}
                            </title>
                        </rect>
                    ))}
                </svg>
            ) : (
                <p>{t("Keine Rohmessungen verfügbar.")}</p>
            )}
            {points.length > 0 && (
                <>
                    <label>
                        {t("Kennzahl")}
                        <select
                            aria-label={t("Kennzahl")}
                            value={metric}
                            onChange={(e) => setMetric(e.target.value)}
                        >
                            {metricKeys.map((k) => (
                                <option key={k} value={k}>
                                    {k}
                                </option>
                            ))}
                        </select>
                    </label>
                    <p>
                        {t("Gemessene Kennzahl")} {metric}
                        {t("; Skala 0 bis")} {maxMetric.toFixed(2)}. Lücken
                        bleiben ohne Messpunkt.
                    </p>
                    <svg
                        role="img"
                        aria-labelledby={metricTitle}
                        viewBox="0 0 700 90"
                        className="status-chart"
                    >
                        <title id={metricTitle}>
                            {t("Einzelmessungen für")} {metric}
                            {t("; numerische Werte in der Tabelle.")}
                        </title>
                        {points.map((p, i) =>
                            typeof numeric[i] === "number" ? (
                                <circle
                                    key={i}
                                    cx={8 + ((values[i] - min) / span) * 680}
                                    cy={
                                        75 -
                                        (Number(numeric[i]) / maxMetric) * 60
                                    }
                                    r={4}
                                    className="point-metric"
                                >
                                    <title>
                                        {time(p.checked_at)}:{" "}
                                        {String(numeric[i])}
                                    </title>
                                </circle>
                            ) : null,
                        )}
                    </svg>
                </>
            )}
            {points.length > 0 && (
                <div
                    className="table-scroll"
                    tabIndex={0}
                    role="region"
                    aria-label={t("Scrollbare Tabelle")}
                >
                    <table>
                        <caption>
                            {t(
                                "Messwerte als zugängliche Diagrammalternative (höchstens 100 aktuelle Punkte)",
                            )}
                        </caption>
                        <thead>
                            <tr>
                                <th>{t("Zeitpunkt")}</th>
                                <th>{t("Status")}</th>
                                <th>{t("Dauer")}</th>
                                <th>{t("Aggregierte Kennzahlen")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {points.map((p, i) => (
                                <tr key={i}>
                                    <td>{time(p.checked_at)}</td>
                                    <td>
                                        {labels[String(p.result)] ??
                                            String(p.result)}
                                    </td>
                                    <td>
                                        {String(p.duration_ms)} {t("ms")}
                                    </td>
                                    <td>{JSON.stringify(p.metrics)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </>
    );
}
