import SafePreview from "./NotificationPreview";
import VersionHistory from "./NotificationHistory";
import { translateMessage, t, localized, useLocale } from "../i18n";
import WeeklyReports from "./WeeklyReports";
import { useState } from "react";
import { z } from "zod";
import { api } from "../api";
import { useData, State, Card, Facts, Pagination } from "../ui";
import {
    Allowed,
    Modal,
    DraftGuard,
    EditForm,
    Inputs,
    reason,
    options,
    type Field,
    type Mutation,
} from "./Form";
import {
    row,
    itemList,
    listing,
    version,
    text,
    selected,
    events,
    priorities,
    type Row,
} from "./contracts";
const base = "/api/v1/dashboard/notifications";
const common: Field[] = localized([
    { key: "enabled", label: "Benachrichtigungen aktiv", type: "checkbox" },
    {
        key: "mode",
        label: "Versandform",
        type: "select",
        required: true,
        options: [
            { id: "immediate", name: "Einzelbenachrichtigung" },
            { id: "digest", name: "Digest" },
        ],
    },
    {
        key: "minimum_priority",
        label: "Mindestpriorität",
        type: "select",
        required: true,
        options: options(priorities),
    },
    {
        key: "digest_hours",
        label: "Digest-Zeitraum",
        type: "select",
        required: true,
        options: [
            { id: "1", name: "Stündlich" },
            { id: "24", name: "Täglich" },
            { id: "168", name: "Wöchentlich" },
        ],
    },
    {
        key: "event_types",
        label: "Ereignisse",
        type: "multi",
        options: options(events),
    },
]);
const quiet: Field[] = localized([
    { key: "quiet_enabled", label: "Ruhezeiten verwenden", type: "checkbox" },
    {
        key: "timezone",
        label: "IANA-Zeitzone",
        required: true,
        max: 64,
        hint: "Zum Beispiel Europe/Berlin",
    },
    { key: "quiet_start", label: "Ruhezeit beginnt", type: "time" },
    { key: "quiet_end", label: "Ruhezeit endet", type: "time" },
    {
        key: "quiet_weekdays",
        label: "Wochentage mit Ruhezeit",
        type: "multi",
        options: [
            "Montag",
            "Dienstag",
            "Mittwoch",
            "Donnerstag",
            "Freitag",
            "Samstag",
            "Sonntag",
        ].map((name, id) => ({ id: String(id), name })),
    },
]);
function initial(config: Row): Row {
    const q = config.quiet as Row | null;
    return {
        ...config,
        quiet_enabled: !!q,
        timezone: q?.timezone ?? config.timezone ?? "Europe/Berlin",
        quiet_start: q?.start ?? "22:00",
        quiet_end: q?.end ?? "07:00",
        quiet_weekdays: (
            (q?.weekdays as number[] | undefined) ?? [0, 1, 2, 3, 4, 5, 6]
        ).map(String),
    };
}
function quietValue(v: Row) {
    return v.quiet_enabled
        ? {
              timezone: v.timezone,
              start: v.quiet_start,
              end: v.quiet_end,
              weekdays: selected(v.quiet_weekdays).map(Number),
          }
        : null;
}
function quietCheck(v: Row): string | null {
    try {
        new Intl.DateTimeFormat("de", { timeZone: String(v.timezone) });
    } catch {
        return t("Bitte eine gültige IANA-Zeitzone angeben.");
    }
    return v.quiet_enabled &&
        (!v.quiet_start ||
            !v.quiet_end ||
            v.quiet_start === v.quiet_end ||
            selected(v.quiet_weekdays).length === 0)
        ? t(
              "Ruhezeiten benötigen verschiedene Anfangs-/Endzeiten und mindestens einen Wochentag.",
          )
        : null;
}
export function Preferences() {
    useLocale();
    const result = useData(base + "/preferences", row);
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [notice, setNotice] = useState("");
    return (
        <>
            <h1>{t("Benachrichtigungspräferenzen")}</h1>
            <p>
                {t(
                    "Neue Findings werden nach dem vollständigen Scan in einem Bericht pro Server zusammengefasst. Hier legst du deine Benachrichtigungspräferenzen und den Wochenbericht fest.",
                )}
            </p>
            {notice && <p role="status">{translateMessage(notice)}</p>}
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <Card title={t("Bestätigte Einstellungen")}>
                    <Facts values={result.data} />
                    <Allowed permission="notification:preferences:update">
                        <button
                            onClick={() => {
                                const r = result.data!;
                                setOperation({
                                    title: t(
                                        "Eigene Benachrichtigungspräferenzen ändern",
                                    ),
                                    path: base + "/preferences",
                                    method: "PUT",
                                    version: version(r),
                                    stepUp: false,
                                    fields: [
                                        ...common.filter(
                                            (field) =>
                                                ![
                                                    "mode",
                                                    "digest_hours",
                                                ].includes(field.key),
                                        ),
                                        ...quiet,
                                        { ...reason, max: 1024 },
                                    ],
                                    initial: initial(r.config as Row),
                                    validate: quietCheck,
                                    payload: (v) => ({
                                        reason: v.reason,
                                        preferences: {
                                            enabled: v.enabled,
                                            mode: v.mode,
                                            minimum_priority:
                                                v.minimum_priority,
                                            digest_hours: Number(
                                                v.digest_hours,
                                            ),
                                            timezone: v.timezone,
                                            language: "de",
                                            quiet: quietValue(v),
                                            event_types: v.event_types,
                                        },
                                    }),
                                });
                            }}
                        >
                            {t("Präferenzen bearbeiten")}
                        </button>
                    </Allowed>
                </Card>
            )}
            <WeeklyReports />
            {operation && (
                <EditForm
                    operation={operation}
                    onCancel={() => setOperation(null)}
                    onReload={() => {
                        setOperation(null);
                        result.reload();
                    }}
                    onDone={() => {
                        setOperation(null);
                        setNotice(t("Präferenzen gespeichert."));
                        result.reload();
                    }}
                />
            )}
        </>
    );
}
export function Rules() {
    useLocale();
    const [offset, setOffset] = useState(0);
    const [history, setHistory] = useState<string | null>(null);
    const result = useData(
        `/api/v1/dashboard/administration/notification-rules?limit=25&offset=${offset}`,
        listing,
    );
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [notice, setNotice] = useState("");
    const fields: Field[] = [
        ...common,
        {
            key: "priority_direction",
            label: t("Prioritätsänderung"),
            type: "select",
            required: true,
            options: [
                { id: "increase", name: t("Nur Erhöhung") },
                { id: "any", name: t("Alle Änderungen") },
            ],
        },
        {
            key: "lifecycle",
            label: t("Lifecycle-Bedingung"),
            type: "multi",
            options: options(["open", "in_progress", "resolved", "closed"]),
        },
        {
            key: "technical",
            label: t("Technische Bedingung"),
            type: "multi",
            options: options([
                "affected",
                "potentially_affected",
                "unknown",
                "not_affected",
                "not_applicable",
            ]),
        },
        { key: "kev_only", label: t("Nur aktuelle KEV"), type: "checkbox" },
        {
            key: "minimum_cvss",
            label: t("CVSS-Untergrenze (optional)"),
            type: "number",
            min: 0,
            max: 10,
            step: "0.1",
        },
        {
            key: "minimum_epss",
            label: t("EPSS-Untergrenze 0..1 (optional)"),
            type: "number",
            min: 0,
            max: 1,
            step: "0.001",
        },
        {
            key: "recipients",
            label: t("Zulässige Empfängergruppe"),
            type: "select",
            required: true,
            options: [
                {
                    id: "server_owner",
                    name: t("Benutzer, der den Server angelegt hat"),
                },
                { id: "assignee", name: t("Zuständige Bearbeiter") },
                { id: "administrators", name: t("Administratoren") },
                { id: "authorized", name: t("Aktuell berechtigte Benutzer") },
            ],
        },
        ...quiet,
        { key: "mandatory", label: t("Pflichtmeldung"), type: "checkbox" },
        {
            key: "critical_bypass",
            label: t("Kritische Meldungen umgehen Ruhezeit"),
            type: "checkbox",
        },
        {
            key: "suppress_active_exception",
            label: t("Bei aktiver Ausnahme unterdrücken"),
            type: "checkbox",
        },
        {
            key: "rate_per_hour",
            label: t("Maximal pro Stunde"),
            type: "number",
            required: true,
            min: 1,
            max: 100,
        },
        {
            key: "max_deferral_hours",
            label: t("Maximale Zurückstellung (Stunden)"),
            type: "number",
            required: true,
            min: 1,
            max: 720,
        },
        {
            key: "exception_warning_hours",
            label: t("Ausnahmevorwarnung (Stunden)"),
            type: "number",
            required: true,
            min: 1,
            max: 720,
        },
        {
            key: "allowed_domains",
            label: t("Erlaubte Empfängerdomains, eine pro Zeile"),
            type: "textarea",
            max: 13000,
        },
        { ...reason, max: 1024 },
    ];
    function edit(r?: Row) {
        const config = r?.config as Row | undefined;
        setOperation({
            title: r
                ? t("Benachrichtigungsregel ") +
                  text(r, "rule_key") +
                  t(" bearbeiten")
                : t("Benachrichtigungsregel erstellen"),
            path: base + "/rules" + (r ? "/" + text(r, "rule_key") : ""),
            method: r ? "PUT" : "POST",
            version: r ? version(r) : 0,
            critical: true,
            fields,
            initial: initial({
                ...config,
                enabled: config?.enabled ?? false,
                mode: config?.mode ?? "immediate",
                minimum_priority: config?.minimum_priority ?? "high",
                digest_hours: config?.digest_hours ?? 24,
                event_types: config?.event_types ?? events,
                priority_direction: config?.priority_direction ?? "increase",
                lifecycle: config?.lifecycle ?? [],
                technical: config?.technical ?? [],
                recipients: config?.recipients ?? "assignee",
                rate_per_hour: config?.rate_per_hour ?? 10,
                max_deferral_hours: config?.max_deferral_hours ?? 168,
                exception_warning_hours: config?.exception_warning_hours ?? 24,
                allowed_domains:
                    (config?.allowed_domains as string[] | undefined)?.join(
                        "\n",
                    ) ?? "",
            }),
            validate: (v) =>
                quietCheck(v) ??
                (selected(v.event_types).length === 0
                    ? t("Mindestens ein unterstütztes Ereignis auswählen.")
                    : null),
            payload: (v) => ({
                reason: v.reason,
                rule: {
                    ...Object.fromEntries(
                        [
                            ...common,
                            ...fields.filter((f) =>
                                [
                                    "priority_direction",
                                    "lifecycle",
                                    "technical",
                                    "kev_only",
                                    "minimum_cvss",
                                    "minimum_epss",
                                    "recipients",
                                    "mandatory",
                                    "critical_bypass",
                                    "suppress_active_exception",
                                    "rate_per_hour",
                                    "max_deferral_hours",
                                    "exception_warning_hours",
                                ].includes(f.key),
                            ),
                        ].map((f) => [
                            f.key,
                            v[f.key] ?? (f.type === "checkbox" ? false : null),
                        ]),
                    ),
                    digest_hours: Number(v.digest_hours),
                    quiet: quietValue(v),
                    allowed_domains: String(v.allowed_domains ?? "")
                        .split("\n")
                        .map((s) => s.trim())
                        .filter(Boolean),
                },
            }),
        });
    }
    return (
        <>
            <h1>{t("Benachrichtigungsregeln")}</h1>
            <p>
                {t(
                    "Neue Regeln starten deaktiviert. Aktivierung ist eine ausdrückliche, versionierte Änderung mit aktueller Rechteprüfung. Keine freie Codeausführung und kein freier Testversand.",
                )}
            </p>
            {notice && <p role="status">{translateMessage(notice)}</p>}
            <Allowed permission="notification:rule:manage">
                <button onClick={() => edit()}>{t("Regel erstellen")}</button>
            </Allowed>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                result.data.items.map((r) => (
                    <Card
                        key={text(r, "id")}
                        title={t("Regel {0} · Version {1}", [
                            text(r, "rule_key"),
                            String(r.version),
                        ])}
                    >
                        <Facts values={r} />
                        <button
                            onClick={() =>
                                setHistory(
                                    history === text(r, "rule_key")
                                        ? null
                                        : text(r, "rule_key"),
                                )
                            }
                        >
                            {t("Regelversionen vergleichen")}
                        </button>
                        {history === text(r, "rule_key") && (
                            <VersionHistory
                                kind="rules"
                                identity={text(r, "rule_key")}
                            />
                        )}
                        <Allowed permission="notification:rule:manage">
                            <button onClick={() => edit(r)}>
                                {t("Regel bearbeiten oder aktivieren")}
                            </button>
                        </Allowed>
                    </Card>
                ))
            )}
            {result.data && (
                <Pagination
                    offset={offset}
                    total={result.data.total}
                    onChange={setOffset}
                />
            )}
            {operation && (
                <EditForm
                    key={operation.title}
                    operation={operation}
                    onCancel={() => setOperation(null)}
                    onReload={() => {
                        setOperation(null);
                        result.reload();
                    }}
                    onDone={() => {
                        setOperation(null);
                        setNotice(
                            t(
                                "Neue Regelversion bestätigt. Frühere Entscheidungen bleiben unverändert.",
                            ),
                        );
                        result.reload();
                    }}
                />
            )}
        </>
    );
}
const previewSchema = z.object({
    subject: z.string(),
    text: z.string(),
    html: z.string(),
});
export function Templates() {
    useLocale();
    const [nextTemplate, setNextTemplate] = useState<Row | null | undefined>(
        undefined,
    );
    const [history, setHistory] = useState<string | null>(null);
    const result = useData(base + "/templates", itemList);
    const [template, setTemplate] = useState<Row | null>(null);
    const [preview, setPreview] = useState<z.infer<
        typeof previewSchema
    > | null>(null);
    const [error, setError] = useState("");
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [notice, setNotice] = useState("");
    const fields: Field[] = [
        { key: "subject", label: t("Betreff"), required: true, max: 160 },
        {
            key: "text",
            label: t("Textversion"),
            type: "textarea",
            required: true,
            max: 8192,
        },
        {
            key: "html",
            label: t("HTML-Version"),
            type: "textarea",
            required: true,
            max: 8192,
        },
    ];
    async function show() {
        if (!template) return;
        setError("");
        setPreview(null);
        try {
            setPreview(
                await api(
                    "/api/v1/dashboard/administration/templates/preview",
                    previewSchema,
                    {
                        method: "POST",
                        body: {
                            name: template.name,
                            language: "de",
                            subject: template.subject,
                            text: template.text,
                            html: template.html,
                        },
                    },
                ),
            );
        } catch (e) {
            setError(
                e instanceof Error ? e.message : t("Vorschau abgewiesen."),
            );
        }
    }
    return (
        <>
            <h1>{t("E-Mail-Vorlagen")}</h1>
            {!operation && (
                <DraftGuard
                    dirty={template !== null}
                    onDiscard={() => setTemplate(null)}
                />
            )}
            <p>
                {t("Unterstützte Variablen:")} {"${title}"}, {"${items}"},{" "}
                {"${link}"}. Keine Zugangsdaten, externen Ressourcen oder
                Testempfänger eintragen. HTML wird im Backend gegen die
                vorhandene endliche Tagliste validiert.
            </p>
            {notice && <p role="status">{translateMessage(notice)}</p>}
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                result.data.items.map((r) => (
                    <Card
                        key={text(r, "id")}
                        title={t("{0} · Version {1}", [
                            text(r, "name"),
                            String(r.version),
                        ])}
                    >
                        <Facts
                            values={{
                                Betreff: (r.content as Row).subject,
                                Text: (r.content as Row).text,
                                HTML: (r.content as Row).html,
                            }}
                        />
                        <button
                            onClick={() =>
                                setHistory(
                                    history === text(r, "name")
                                        ? null
                                        : text(r, "name"),
                                )
                            }
                        >
                            {t("Vorlagenversionen vergleichen")}
                        </button>
                        {history === text(r, "name") && (
                            <VersionHistory
                                kind="templates"
                                identity={text(r, "name")}
                            />
                        )}
                        <button
                            onClick={() => {
                                if (template)
                                    setNextTemplate({
                                        ...r,
                                        ...(r.content as Row),
                                    });
                                else
                                    setTemplate({
                                        ...r,
                                        ...(r.content as Row),
                                    });
                                setPreview(null);
                            }}
                        >
                            {t("Vorlage zur Vorschau auswählen")}
                        </button>
                    </Card>
                ))
            )}
            {template && (
                <Card title={t("Vorlage bearbeiten und prüfen")}>
                    <fieldset disabled={!!operation}>
                        <Inputs
                            fields={fields}
                            values={template}
                            set={(k, v) => {
                                setTemplate({ ...template, [k]: v });
                                setPreview(null);
                            }}
                        />
                    </fieldset>
                    <div className="actions">
                        <button onClick={() => void show()}>
                            {t("Sichere Vorschau erzeugen")}
                        </button>
                        <Allowed permission="notification:template:manage">
                            <button
                                onClick={() =>
                                    setOperation({
                                        title: t("Vorlage {0} speichern", [
                                            String(template.name),
                                        ]),
                                        path: base + "/templates",
                                        method: "POST",
                                        version: version(template),
                                        critical: true,
                                        fields: [{ ...reason, max: 1024 }],
                                        payload: (v) => ({
                                            reason: v.reason,
                                            template: {
                                                name: template.name,
                                                language: "de",
                                                subject: template.subject,
                                                text: template.text,
                                                html: template.html,
                                            },
                                        }),
                                    })
                                }
                            >
                                {t("Vorlage speichern")}
                            </button>
                        </Allowed>
                        <button onClick={() => setNextTemplate(null)}>
                            {t("Bearbeitung schließen")}
                        </button>
                    </div>
                    {error && <p role="alert">{translateMessage(error)}</p>}
                    {preview && (
                        <section aria-label={t("Kontrollierte Vorschau")}>
                            <h3>{preview.subject}</h3>
                            <pre>{preview.text}</pre>
                            <SafePreview html={preview.html} />
                        </section>
                    )}
                </Card>
            )}
            {nextTemplate !== undefined && (
                <Modal
                    title={t("Ungespeicherte Vorlagenänderungen")}
                    onCancel={() => setNextTemplate(undefined)}
                >
                    <p>
                        {t(
                            "Der lokale Vorlagenentwurf wurde noch nicht gespeichert.",
                        )}
                    </p>
                    <div className="actions">
                        <button
                            autoFocus
                            onClick={() => setNextTemplate(undefined)}
                        >
                            {t("Weiter bearbeiten")}
                        </button>
                        <button
                            onClick={() => {
                                setTemplate(nextTemplate);
                                setNextTemplate(undefined);
                                setPreview(null);
                            }}
                        >
                            {t("Änderungen verwerfen")}
                        </button>
                    </div>
                </Modal>
            )}
            {operation && (
                <EditForm
                    operation={{ ...operation, dirty: true }}
                    onCancel={() => setOperation(null)}
                    onReload={() => {
                        setOperation(null);
                        setTemplate(null);
                        result.reload();
                    }}
                    onDone={() => {
                        setOperation(null);
                        setTemplate(null);
                        setPreview(null);
                        setNotice(t("Neue Vorlagenversion bestätigt."));
                        result.reload();
                    }}
                />
            )}
        </>
    );
}
