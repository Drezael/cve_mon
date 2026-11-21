import { translateMessage, t, localized, useLocale } from "../i18n";
import { useEffect, useRef, useState } from "react";
import { z } from "zod";
import { api } from "../api";
import { Card, State, useData } from "../ui";

const schema = z.object({
    enabled: z.boolean(),
    host: z.string(),
    port: z.number(),
    sender: z.string(),
    recipients: z.array(z.string()),
    id: z.string().nullable(),
    version: z.number(),
    state: z.string(),
    username: z.string(),
    password_configured: z.boolean(),
    created_at: z.string().nullable(),
    finished_at: z.string().nullable(),
    error_code: z.string().nullable(),
    execution_id: z.string().nullable(),
    mode: z.enum(["system", "custom"]).optional(),
    system_available: z.boolean().optional(),
});
type Settings = z.infer<typeof schema>;
const base = "/api/v1/dashboard/administration/smtp";
const states: Record<string, string> = localized({
    unconfigured: "Noch nicht eingerichtet",
    waiting: "Wartet auf n8n",
    authorized: "Von n8n freigegeben",
    applying: "Wird angewendet",
    applied: "Konfiguration angewendet",
    failed: "Anwendung fehlgeschlagen",
    cancelled: "Abgebrochen",
});
export default function SMTPSettings({
    personal = false,
}: {
    personal?: boolean;
}) {
    useLocale();
    const endpoint = personal ? "/api/v1/dashboard/notifications/mail" : base;
    const result = useData(endpoint, schema);
    return (
        <>
            <h1>
                {personal
                    ? t("Meine Mail-Einstellungen")
                    : t("Zentrale SMTP-Einstellungen")}
            </h1>
            <p>
                {personal
                    ? t(
                          "Lege deine Empfängeradressen fest. Verwende den zentralen SMTP-Server der Administration oder deinen eigenen Server.",
                      )
                    : t(
                          "Systemweiter SMTP-Server für Benutzer, die den zentralen Versand auswählen. Empfängeradressen werden in den persönlichen Einstellungen festgelegt.",
                      )}
            </p>
            <button onClick={result.reload}>{t("Status aktualisieren")}</button>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <Form
                    key={result.data.version}
                    value={result.data}
                    reload={result.reload}
                    personal={personal}
                    endpoint={endpoint}
                />
            )}
        </>
    );
}
function Form({
    value,
    reload,
    personal,
    endpoint,
}: {
    value: Settings;
    reload: () => void;
    personal: boolean;
    endpoint: string;
}) {
    useLocale();
    const [mode, setMode] = useState(value.mode ?? "system");
    const custom = !personal || mode === "custom";
    const [enabled, setEnabled] = useState(value.enabled),
        [host, setHost] = useState(value.host),
        [port, setPort] = useState(String(value.port));
    const localCapture = host === "mailhog.cve.test" && Number(port) === 1025;
    const [username, setUsername] = useState(value.username),
        [password, setPassword] = useState(""),
        [sender, setSender] = useState(value.sender),
        [recipients, setRecipients] = useState(value.recipients.join("\n"));
    const [busy, setBusy] = useState(false),
        [error, setError] = useState<Error | null>(null),
        [message, setMessage] = useState("");
    const idempotency = useRef<string | null>(null);
    const pending = ["waiting", "authorized", "applying"].includes(value.state);
    async function save() {
        if (busy || pending) return;
        setBusy(true);
        setError(null);
        idempotency.current ??= crypto.randomUUID();
        try {
            await api(endpoint, schema, {
                method: "PUT",
                idempotencyKey: idempotency.current,
                body: {
                    version: value.version,
                    enabled: personal ? mode === "custom" : enabled,
                    ...(personal ? { mode } : {}),
                    host: custom ? host : value.host,
                    port: custom ? Number(port) : value.port,
                    username: custom ? username : value.username,
                    password: custom ? password || null : null,
                    sender: custom ? sender : value.sender,
                    recipients: (personal ? recipients : "")
                        .split(/[\n,;]/)
                        .map((s) => s.trim())
                        .filter(Boolean),
                },
            });
            setPassword("");
            idempotency.current = null;
            setMessage(
                t("Konfiguration gespeichert und in die n8n-Queue eingereiht."),
            );
            reload();
        } catch (e) {
            setError(e as Error);
        } finally {
            setBusy(false);
        }
    }
    return (
        <>
            <Card title={t("SMTP-Konfiguration")}>
                <p role="status">
                    {states[value.state] ?? value.state}
                    {value.execution_id &&
                        t(" · n8n-Ausführung {0}", [value.execution_id])}
                </p>
                {value.error_code && (
                    <p role="alert">
                        {t(
                            "Die Konfiguration konnte nicht angewendet werden. Die vorherige Konfiguration bleibt erhalten. Fehler:",
                        )}{" "}
                        {value.error_code}
                    </p>
                )}
                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        void save();
                    }}
                    onChange={() => {
                        idempotency.current = null;
                        setMessage("");
                    }}
                >
                    <fieldset disabled={busy || pending}>
                        <legend>{t("Server und Zugangsdaten")}</legend>
                        {personal && (
                            <>
                                <label htmlFor="personal-smtp-mode">
                                    {t("SMTP-Auswahl")}
                                </label>
                                <select
                                    id="personal-smtp-mode"
                                    value={mode}
                                    onChange={(e) =>
                                        setMode(
                                            e.target.value as
                                                "system" | "custom",
                                        )
                                    }
                                >
                                    <option value="system">
                                        {t("Zentralen SMTP-Server verwenden")}
                                    </option>
                                    <option value="custom">
                                        {t("Eigenen SMTP-Server verwenden")}
                                    </option>
                                </select>
                                {mode === "system" && (
                                    <p role="status">
                                        {value.system_available
                                            ? t(
                                                  "Der zentrale SMTP-Server ist verfügbar.",
                                              )
                                            : t(
                                                  "Der zentrale SMTP-Server wurde noch nicht aktiviert. Deine Empfängeradressen können bereits gespeichert werden.",
                                              )}
                                    </p>
                                )}
                            </>
                        )}
                        {!personal && (
                            <label>
                                <input
                                    type="checkbox"
                                    checked={enabled}
                                    onChange={(e) =>
                                        setEnabled(e.target.checked)
                                    }
                                />
                                {t("Zentralen E-Mail-Versand aktivieren")}
                            </label>
                        )}
                        {custom && (
                            <>
                                <label>
                                    {t("SMTP-Server")}
                                    <input
                                        value={host}
                                        onChange={(e) =>
                                            setHost(e.target.value)
                                        }
                                        maxLength={253}
                                        required={personal || enabled}
                                        placeholder="smtp.example.org"
                                    />
                                </label>
                                <label>
                                    {t("SMTP-Port")}
                                    <input
                                        type="number"
                                        min={1}
                                        max={65535}
                                        value={port}
                                        onChange={(e) =>
                                            setPort(e.target.value)
                                        }
                                        required
                                    />
                                </label>
                                <p>
                                    {localCapture
                                        ? t(
                                              "Lokaler MailHog-Testserver: Nachrichten werden lokal aufgefangen, ohne Anmeldung oder STARTTLS.",
                                          )
                                        : t(
                                              "Verbindung mit verpflichtendem STARTTLS und Zertifikatsprüfung, üblicherweise Port 587. Port 465 mit implizitem TLS wird derzeit nicht unterstützt.",
                                          )}
                                </p>
                                <label>
                                    {t("SMTP-Benutzername")}
                                    <input
                                        value={username}
                                        onChange={(e) =>
                                            setUsername(e.target.value)
                                        }
                                        maxLength={256}
                                        required={
                                            (personal || enabled) &&
                                            !localCapture
                                        }
                                        autoComplete="off"
                                    />
                                </label>
                                <label>
                                    {t("SMTP-Passwort")}
                                    <input
                                        type="password"
                                        value={password}
                                        onChange={(e) =>
                                            setPassword(e.target.value)
                                        }
                                        maxLength={4096}
                                        required={
                                            (personal || enabled) &&
                                            !localCapture &&
                                            !value.password_configured
                                        }
                                        autoComplete="new-password"
                                    />
                                </label>
                                <p>
                                    {value.password_configured
                                        ? t(
                                              "Passwort ist gespeichert. Leer lassen, um es beizubehalten.",
                                          )
                                        : t(
                                              "Es ist noch kein SMTP-Passwort gespeichert.",
                                          )}{" "}
                                    {t(
                                        "Gespeicherte Passwörter werden nicht angezeigt.",
                                    )}
                                </p>
                                <label>
                                    {t("Absenderadresse")}
                                    <input
                                        type="email"
                                        value={sender}
                                        onChange={(e) =>
                                            setSender(e.target.value)
                                        }
                                        maxLength={254}
                                        required={personal || enabled}
                                    />
                                </label>
                            </>
                        )}
                        {personal && (
                            <>
                                <label htmlFor="personal-smtp-recipients">
                                    {t("Meine Empfängeradressen")}
                                </label>
                                <textarea
                                    id="personal-smtp-recipients"
                                    value={recipients}
                                    onChange={(e) =>
                                        setRecipients(e.target.value)
                                    }
                                    required={personal || enabled}
                                    rows={4}
                                />
                            </>
                        )}
                        {personal && (
                            <p>
                                {t(
                                    "Eine Adresse pro Zeile, maximal 20 Adressen. Komma und Semikolon sind ebenfalls möglich. Alle Adressen erhalten nur deine berechtigten Benachrichtigungen.",
                                )}
                            </p>
                        )}
                        <button type="submit">
                            {busy
                                ? t("Wird gespeichert …")
                                : pending
                                  ? t("Wartet auf Anwendung über n8n")
                                  : t("Speichern und über n8n anwenden")}
                        </button>
                    </fieldset>
                    {error && (
                        <p role="alert">{translateMessage(error.message)}</p>
                    )}
                    {message && (
                        <p role="status">{translateMessage(message)}</p>
                    )}
                </form>
            </Card>
            <MailTest
                endpoint={endpoint}
                disabled={
                    pending ||
                    (personal
                        ? value.mode === "custom"
                            ? value.state !== "applied"
                            : !value.system_available
                        : value.state !== "applied" || !value.enabled)
                }
            />
            <p>
                {t(
                    "Die Übernahme lädt die native Mail-Konfiguration nach. Die vorhandene Mailqueue bleibt erhalten. Den Fortschritt kannst du mit „Status aktualisieren“ prüfen.",
                )}
            </p>
        </>
    );
}

const testSchema = z.object({
    id: z.string().nullable(),
    state: z.enum([
        "unconfigured",
        "waiting",
        "authorized",
        "running",
        "sent",
        "failed",
        "cancelled",
    ]),
    error_code: z.string().nullable(),
    created_at: z.string().nullable().optional(),
});
const testStates: Record<string, string> = localized({
    unconfigured: "Noch kein Test angefordert.",
    waiting: "Test wartet auf n8n.",
    authorized: "Test von n8n freigegeben.",
    running: "Testmail wird versendet …",
    sent: "Der SMTP-Server hat die Testmail angenommen. Prüfe den Posteingang und gegebenenfalls den Spamordner.",
    failed: "Der Mailtest ist fehlgeschlagen.",
    cancelled: "Der Mailtest wurde abgebrochen.",
});
const testErrors: Record<string, string> = localized({
    SMTP_AUTHENTICATION_FAILED:
        "Anmeldung fehlgeschlagen. Prüfe Benutzername und Passwort.",
    SMTP_TLS_FAILED:
        "Die sichere STARTTLS-Verbindung konnte nicht hergestellt werden.",
    SMTP_CONNECTION_FAILED: "Der SMTP-Server konnte nicht erreicht werden.",
    SMTP_REJECTED:
        "Der SMTP-Server hat die Nachricht oder einen Empfänger abgelehnt.",
    SMTP_SETTINGS_CHANGED:
        "Die Einstellungen oder Berechtigungen haben sich geändert. Starte den Test erneut.",
    SMTP_OUTCOME_UNKNOWN:
        "Der Versandstatus ist unklar. Prüfe den Posteingang, bevor du erneut testest.",
    REQUESTER_UNAVAILABLE:
        "Der anfordernde Benutzer ist nicht mehr berechtigt.",
});
function MailTest({
    endpoint,
    disabled,
}: {
    endpoint: string;
    disabled: boolean;
}) {
    useLocale();
    const result = useData(endpoint + "/test", testSchema);
    const [recipient, setRecipient] = useState("");
    const [requested, setRequested] = useState<z.infer<
        typeof testSchema
    > | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<Error | null>(null);
    const identity = useRef<string | null>(null);
    const current =
        requested &&
        (!result.data?.created_at ||
            (requested.created_at ?? "") > result.data.created_at)
            ? requested
            : result.data;
    const pending = ["waiting", "authorized", "running"].includes(
        current?.state ?? "",
    );
    useEffect(() => {
        if (!pending) return;
        const timer = setTimeout(result.reload, 1500);
        return () => clearTimeout(timer);
    }, [pending, result.reload, current]);
    async function send() {
        if (busy || disabled || pending) return;
        setBusy(true);
        setError(null);
        identity.current ??= crypto.randomUUID();
        try {
            const queued = await api(endpoint + "/test", testSchema, {
                method: "POST",
                idempotencyKey: identity.current,
                body: { recipient: recipient.trim() || null },
            });
            setRequested(queued);
            identity.current = null;
            result.reload();
        } catch (e) {
            setError(e as Error);
        } finally {
            setBusy(false);
        }
    }
    return (
        <Card title={t("Maileinstellungen testen")}>
            <p>
                {t(
                    "Der Test verwendet die zuletzt angewendeten, gespeicherten Einstellungen. Änderungen im Formular zuerst speichern und anwenden lassen.",
                )}
            </p>
            <form
                onSubmit={(e) => {
                    e.preventDefault();
                    void send();
                }}
            >
                <label htmlFor="smtp-test-recipient">
                    {t("Testempfänger (optional)")}
                </label>
                <input
                    id="smtp-test-recipient"
                    type="email"
                    value={recipient}
                    maxLength={254}
                    onChange={(e) => {
                        setRecipient(e.target.value);
                        identity.current = null;
                    }}
                    disabled={busy || pending}
                />
                <p>
                    {t(
                        "Ohne Angabe werden deine gespeicherten Empfänger verwendet, bei einem zentralen Test deine Benutzer-E-Mail-Adresse.",
                    )}
                </p>
                <button
                    type="submit"
                    disabled={disabled || busy || pending || !result.data}
                >
                    {busy || pending
                        ? t("Testmail wird versendet …")
                        : t("Testmail senden")}
                </button>
            </form>
            {current && <p role="status">{testStates[current.state]}</p>}
            {current?.error_code && (
                <p role="alert">
                    {testErrors[current.error_code] ??
                        t("Der Test konnte nicht ausgeführt werden.")}
                </p>
            )}
            {(error || result.error) && (
                <p role="alert">
                    {translateMessage((error || result.error)?.message)}
                </p>
            )}
        </Card>
    );
}
