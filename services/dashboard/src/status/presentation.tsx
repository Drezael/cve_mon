import { intlLocale, t, localized, useLocale } from "../i18n";

export const labels: Record<string, string> = localized({
    healthy: "Gesund",
    degraded: "Eingeschränkt",
    unavailable: "Nicht verfügbar",
    unknown: "Unbekannt",
    starting: "Startphase",
    maintenance: "Wartung",
    open: "Offen",
    resolved: "Wiederhergestellt",
});
export function StatusBadge({ value }: { value: string }) {
    useLocale();
    return (
        <span className={"status-badge status-" + value}>
            {value === "healthy" ? "✓" : value === "maintenance" ? "◇" : "!"}{" "}
            {labels[value] ?? value}
        </span>
    );
}
export function time(value: unknown) {
    return typeof value === "string"
        ? new Date(value).toLocaleString(intlLocale())
        : t("Noch keine Messung");
}
