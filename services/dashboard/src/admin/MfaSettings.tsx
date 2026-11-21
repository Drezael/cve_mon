import { translateMessage, t, useLocale } from "../i18n";
import { useState, type FormEvent } from "react";
import { z } from "zod";
import { api, authResult } from "../api";
import { useAuth } from "../auth";
import { Card } from "../ui";
import { EditForm, type Mutation } from "./Form";

export function MfaSettings({
    enabled,
    reload,
}: {
    enabled: boolean;
    reload: () => void;
}) {
    useLocale();
    const {
        refresh,
        enrollmentSecret,
        setEnrollmentSecret,
        recoveryCodes,
        setRecoveryCodes,
    } = useAuth();
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [code, setCode] = useState("");
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);

    async function confirm(event: FormEvent) {
        event.preventDefault();
        setBusy(true);
        setError("");
        try {
            const result = await api(
                "/api/v1/auth/mfa/enroll/confirm",
                authResult,
                {
                    method: "POST",
                    body: { code },
                },
            );
            setCode("");
            setEnrollmentSecret(null);
            setRecoveryCodes(result.recovery_codes ?? []);
            reload();
            await refresh(true);
        } catch (e) {
            setError(
                e instanceof Error
                    ? e.message
                    : t("Aktivierung fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    async function cancel() {
        setBusy(true);
        setError("");
        try {
            await api("/api/v1/auth/mfa/enroll/cancel", z.null(), {
                method: "POST",
                body: {},
            });
            setEnrollmentSecret(null);
            setCode("");
        } catch (e) {
            setError(
                e instanceof Error ? e.message : t("Abbruch fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    return (
        <Card title={t("Zwei-Faktor-Anmeldung (optional)")}>
            <p>
                {t("MFA ist")} {enabled ? "aktiviert" : "deaktiviert"}. Sie
                entscheiden selbst, ob Sie zusätzlich zum Passwort eine
                Authenticator-App verwenden.
            </p>
            {error && <p role="alert">{translateMessage(error)}</p>}
            {enrollmentSecret ? (
                <form onSubmit={(event) => void confirm(event)}>
                    <p>
                        {t(
                            "Diesen Schlüssel in Ihrer Authenticator-App hinzufügen und den aktuellen Code bestätigen:",
                        )}
                    </p>
                    <code className="secret">{enrollmentSecret}</code>
                    <label>
                        {t("Sechsstelliger Bestätigungscode")}
                        <input
                            autoComplete="one-time-code"
                            inputMode="numeric"
                            pattern="[0-9]{6}"
                            minLength={6}
                            maxLength={6}
                            required
                            value={code}
                            onChange={(event) => setCode(event.target.value)}
                        />
                    </label>
                    <button disabled={busy} type="submit">
                        {t("MFA aktivieren")}
                    </button>
                    <button
                        disabled={busy}
                        type="button"
                        onClick={() => void cancel()}
                    >
                        {t("Einrichtung abbrechen")}
                    </button>
                </form>
            ) : (
                <div className="actions">
                    <button
                        onClick={() =>
                            setOperation({
                                title: enabled
                                    ? t("MFA erneuern")
                                    : t("MFA einrichten"),
                                path: "/api/v1/auth/mfa/enroll/start",
                                method: "POST",
                                critical: true,
                                fields: [],
                                initial: {},
                            })
                        }
                    >
                        {enabled ? t("MFA erneuern") : t("MFA einrichten")}
                    </button>
                    {enabled && (
                        <button
                            onClick={() =>
                                setOperation({
                                    title: t("MFA deaktivieren"),
                                    path: "/api/v1/auth/mfa/disable",
                                    method: "POST",
                                    critical: true,
                                    fields: [],
                                    initial: {},
                                })
                            }
                        >
                            {t("MFA deaktivieren")}
                        </button>
                    )}
                </div>
            )}
            {recoveryCodes.length > 0 && (
                <section aria-label={t("Wiederherstellungscodes")}>
                    <h2>{t("Wiederherstellungscodes sichern")}</h2>
                    <p>
                        {t(
                            "Diese Codes werden nur einmal angezeigt. Bewahren Sie sie sicher auf.",
                        )}
                    </p>
                    <ul>
                        {recoveryCodes.map((value) => (
                            <li key={value}>
                                <code>{value}</code>
                            </li>
                        ))}
                    </ul>
                    <button onClick={() => setRecoveryCodes([])}>
                        {t("Sicher aufbewahrt")}
                    </button>
                </section>
            )}
            {operation && (
                <EditForm
                    operation={operation}
                    onCancel={() => setOperation(null)}
                    onReload={() => {
                        setOperation(null);
                        reload();
                    }}
                    onDone={(result) => {
                        if (typeof result?.provisioning_uri === "string")
                            setEnrollmentSecret(
                                new URL(
                                    result.provisioning_uri,
                                ).searchParams.get("secret"),
                            );
                        else {
                            setEnrollmentSecret(null);
                            setRecoveryCodes([]);
                        }
                        setOperation(null);
                        reload();
                        void refresh(true);
                    }}
                />
            )}
        </Card>
    );
}
