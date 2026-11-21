import { t, localized, useLocale } from "./i18n";
import { percent } from "./format";

type Risk = {
    current_priority?: string;
    cvss?: Record<string, unknown> | null;
    kev_status?: string;
    kev_is_current?: boolean;
    epss?: Record<string, unknown> | null;
};
const levels = ["unrated", "low", "medium", "high", "critical"];
const names = localized(["Unbekannt", "Niedrig", "Mittel", "Hoch", "Kritisch"]);
export function threatLevel(f: Risk) {
    let rank = Math.max(0, levels.indexOf(f.current_priority ?? "unrated"));
    const raw = f.cvss?.base_score ?? f.cvss?.calculated_score ?? f.cvss?.score;
    const score = raw === null || raw === undefined ? NaN : Number(raw);
    if (Number.isFinite(score) && score >= 0 && score <= 10)
        rank = Math.max(
            rank,
            score >= 9
                ? 4
                : score >= 7
                  ? 3
                  : score >= 4
                    ? 2
                    : score > 0
                      ? 1
                      : 0,
        );
    if (f.kev_status === "present" && f.kev_is_current) rank = 4;
    if (f.epss && f.epss.is_stale === false && Number(f.epss.score) >= 0.1)
        rank = Math.max(rank, 3);
    return { rank, level: levels[rank], label: names[rank], score };
}
export default function Threat({ finding }: { finding: Risk }) {
    useLocale();
    const risk = threatLevel(finding);
    const details = [
        Number.isFinite(risk.score)
            ? t("CVSS {0}/10", [risk.score])
            : t("CVSS unbekannt"),
        finding.kev_status === "present" && finding.kev_is_current
            ? t("Aktive Ausnutzung laut CISA KEV")
            : "",
        finding.epss && finding.epss.is_stale === false
            ? t("EPSS {0}", [percent(finding.epss.score)])
            : "",
    ]
        .filter(Boolean)
        .join(" · ");
    return (
        <div
            className={"threat threat-" + risk.level}
            title={details}
            aria-label={t("Bedrohung: ") + risk.label + ". " + details}
        >
            <strong>{risk.label}</strong>
            <span className="threat-bars" aria-hidden="true">
                {[1, 2, 3, 4].map((i) => (
                    <i key={i} className={i <= risk.rank ? "filled" : ""} />
                ))}
            </span>
            <small>{details}</small>
        </div>
    );
}
