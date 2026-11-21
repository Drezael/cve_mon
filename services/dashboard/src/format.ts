import { intlLocale, t, localized } from "./i18n";
export const labels: Record<string, string> = localized({
    internal: "Intern",
    restricted: "Eingeschränkt erreichbar",
    internet_exposed: "Aus dem Internet erreichbar",
    confirmed: "Bestätigt",
    suspected_false_positive: "Fehlalarm vermutet",
    deadline_approaching: "Frist läuft ab",
    overdue: "Überfällig",
    status_unavailable: "Nicht erreichbar",
    status_recovered: "Wieder verfügbar",
    pending_activation: "Aktivierung ausstehend",
    disabled: "Deaktiviert",
    locked: "Gesperrt",
    authenticated: "Angemeldet",
    accepted: "Zur Verarbeitung angenommen",
    processing: "Verarbeitung läuft",
    completed: "Inventar verarbeitet",
    rejected_after_acceptance: "Nach Annahme abgewiesen",
    digest: "Sammelbenachrichtigung",
    pending: "Noch nicht ausgewertet",
    outdated_matching: "Veraltetes Matching",
    current_matching: "Aktuelles Matching",
    critical: "Kritisch",
    high: "Hoch",
    medium: "Mittel",
    low: "Niedrig",
    unrated: "Nicht bewertet",
    open: "Offen",
    in_progress: "In Bearbeitung",
    resolved: "Behoben",
    closed: "Geschlossen",
    affected: "Betroffen",
    potentially_affected: "Betroffen",
    unknown: "Nicht bewertbar",
    not_affected: "Nicht betroffen",
    not_applicable: "Nicht anwendbar",
    active: "Aktiv",
    archived: "Archiviert",
    current: "Aktuell",
    stale: "Veraltet",
    missing: "Fehlt",
    not_configured: "Keine Altersrichtlinie",
    complete: "Vollständig",
    partial: "Unvollständig",
    failed: "Fehlgeschlagen",
    processed: "Verarbeitet",
    not_collected: "Nicht erfasst",
    confirmed_false_positive: "Fehlalarm bestätigt",
    needs_review: "Prüfung erforderlich",
    unreviewed: "Noch nicht geprüft",
    mitigation_documented: "Maßnahme dokumentiert",
    planned: "Geplant",
    ready: "Bereit",
    leased: "Reserviert",
    submitting: "Übergabe läuft",
    relay_accepted: "Von Postfix angenommen",
    upstream_accepted: "An Smarthost weitergegeben",
    delivery_confirmed: "Zustellung nachgewiesen",
    submission_uncertain: "Annahme unklar",
    retryable_failure: "Wiederholbarer Fehler",
    permanent_failure: "Dauerhafter Fehler",
    suppressed: "Unterdrückt",
    deferred: "Zurückgestellt",
    bounced: "Rückläufer bestätigt",
    cancelled: "Beendet",
    created: "Erstmals erkannt",
    reopened: "Wiedereröffnet",
    confirmed_affected: "Betroffenheit bestätigt",
    priority_changed: "Priorität geändert",
    assigned: "Zuständigkeit geändert",
    exception_approved: "Ausnahme genehmigt",
    exception_approaching: "Ausnahme läuft ab",
    exception_expired: "Ausnahme abgelaufen",
    exception_revoked: "Ausnahme widerrufen",
});
export const label = (value: unknown) =>
    typeof value === "string" ? (labels[value] ?? value) : t("Nicht verfügbar");
export const number = (v: unknown) =>
    typeof v === "number"
        ? new Intl.NumberFormat(intlLocale()).format(v)
        : t("Nicht verfügbar");
export function date(value: unknown) {
    if (typeof value !== "string" || !Number.isFinite(Date.parse(value)))
        return t("Nicht verfügbar");
    return new Intl.DateTimeFormat(intlLocale(), {
        dateStyle: "medium",
        timeStyle: "short",
        timeZone: "Europe/Berlin",
    }).format(new Date(value));
}
export const percent = (v: unknown) =>
    v !== null &&
    v !== undefined &&
    String(v).trim() !== "" &&
    Number.isFinite(Number(v)) &&
    Number(v) >= 0 &&
    Number(v) <= 1
        ? new Intl.NumberFormat(intlLocale(), {
              style: "percent",
              maximumFractionDigits: 2,
          }).format(Number(v))
        : t("Unbekannt");
export function safePath(path: string) {
    return /^\/(dashboard|servers|groups|findings|notifications)(\/[0-9a-f-]{36})?(\?[a-zA-Z0-9%_=&.-]*)?$/.test(
        path,
    )
        ? path
        : "/dashboard";
}
export function safeLink(value: unknown): string | null {
    if (typeof value !== "string") return null;
    try {
        const u = new URL(value);
        return u.protocol === "https:" && !u.username && !u.password
            ? u.href
            : null;
    } catch {
        return null;
    }
}
