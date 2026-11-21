import { translateMessage, t, useLocale } from "../i18n";
import { useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth, authResult } from "../auth";
import { api, ApiError } from "../api";
export default function Login() {
    useLocale();
    const {
        identity,
        enrollmentSecret,
        setEnrollmentSecret,
        refresh,
        logoutError,
        logout,
        recoveryCodes: codes,
        setRecoveryCodes: setCodes,
    } = useAuth();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [code, setCode] = useState("");
    const [recovery, setRecovery] = useState(false);
    const [secret, setSecret] = useState<string | null>(enrollmentSecret);
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    const state = identity?.state;
    const setup = state === "mfa_setup_required" || state === "mfa_recovery";
    const pending = state === "mfa_pending";
    async function submit(e: FormEvent) {
        e.preventDefault();
        setBusy(true);
        setError("");
        try {
            const path = setup
                ? "mfa/enroll/confirm"
                : pending
                  ? recovery
                      ? "mfa/recovery"
                      : "mfa/verify"
                  : "login";
            const r = await api(`/api/v1/auth/${path}`, authResult, {
                method: "POST",
                body: setup || pending ? { code } : { username, password },
            });
            setPassword("");
            setCode("");
            setSecret(null);
            setEnrollmentSecret(null);
            setCodes(r.recovery_codes ?? []);
            await refresh(true);
        } catch (e) {
            setError(
                e instanceof ApiError && [401, 403].includes(e.status)
                    ? t(
                          "Anmeldedaten oder Bestätigungscode ungültig. Bitte erneut versuchen.",
                      )
                    : e instanceof Error
                      ? e.message
                      : t("Anmeldung fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    async function enroll() {
        setBusy(true);
        setError("");
        try {
            const r = await api("/api/v1/auth/mfa/enroll/start", authResult, {
                method: "POST",
                body: {},
            });
            setSecret(
                r.provisioning_uri
                    ? new URL(r.provisioning_uri).searchParams.get("secret")
                    : null,
            );
        } catch (e) {
            setError(
                e instanceof Error
                    ? e.message
                    : t("Einrichtung fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    if (codes.length)
        return (
            <main className="auth">
                <h1>{t("Wiederherstellungscodes sichern")}</h1>
                <p>
                    {t(
                        "Diese Codes werden nur einmal angezeigt. Bewahren Sie sie sicher außerhalb dieses Browsers auf.",
                    )}
                </p>
                <ul>
                    {codes.map((c) => (
                        <li key={c}>
                            <code>{c}</code>
                        </li>
                    ))}
                </ul>
                <button onClick={() => setCodes([])}>
                    {t("Sicher aufbewahrt – fortfahren")}
                </button>
            </main>
        );
    if (state === "authenticated")
        return (
            <Navigate
                replace
                to={
                    identity?.permissions.includes("security:overview:read")
                        ? "/dashboard"
                        : "/servers"
                }
            />
        );
    return (
        <main className="auth">
            <div className="auth-brand">
                <ShieldCheck aria-hidden="true" size={36} />
                <span>{t("CVE MONITOR")}</span>
            </div>
            <h1>
                {setup
                    ? t("MFA einrichten")
                    : pending
                      ? t("Anmeldung bestätigen")
                      : t("Willkommen zurück")}
            </h1>
            <p>
                {setup
                    ? t("Verbinden Sie Ihre Authenticator-App.")
                    : pending
                      ? t("Geben Sie Ihren Bestätigungscode ein.")
                      : t("Melden Sie sich mit Ihrem persönlichen Konto an.")}
            </p>
            {logoutError && (
                <div role="alert" className="notice">
                    <p>{translateMessage(logoutError)}</p>
                    <button onClick={() => void logout()}>
                        {t("Abmeldung erneut versuchen")}
                    </button>
                </div>
            )}
            {error && (
                <p role="alert" className="notice">
                    {translateMessage(error)}
                </p>
            )}
            {setup && !secret ? (
                <button onClick={() => void enroll()} disabled={busy}>
                    {t("Authenticator einrichten")}
                </button>
            ) : (
                <form onSubmit={(e) => void submit(e)}>
                    {!pending && !setup ? (
                        <>
                            <label>
                                {t("Benutzername")}
                                <input
                                    name="username"
                                    autoComplete="username"
                                    required
                                    value={username}
                                    onChange={(e) =>
                                        setUsername(e.target.value)
                                    }
                                    maxLength={128}
                                />
                            </label>
                            <label>
                                {t("Passwort")}
                                <input
                                    name="password"
                                    type="password"
                                    autoComplete="current-password"
                                    required
                                    value={password}
                                    onChange={(e) =>
                                        setPassword(e.target.value)
                                    }
                                    maxLength={1024}
                                />
                            </label>
                        </>
                    ) : (
                        <>
                            {secret && (
                                <>
                                    <p>
                                        {t(
                                            "Schlüssel manuell in der Authenticator-App hinzufügen:",
                                        )}
                                    </p>
                                    <code className="secret">{secret}</code>
                                </>
                            )}
                            <label>
                                {recovery
                                    ? t("Wiederherstellungscode")
                                    : t("Sechsstelliger Bestätigungscode")}
                                <input
                                    autoComplete="one-time-code"
                                    inputMode={recovery ? "text" : "numeric"}
                                    required
                                    minLength={recovery ? 20 : 6}
                                    maxLength={recovery ? 80 : 6}
                                    pattern={recovery ? undefined : "[0-9]{6}"}
                                    value={code}
                                    onChange={(e) => setCode(e.target.value)}
                                />
                            </label>
                        </>
                    )}
                    <button type="submit" disabled={busy}>
                        {busy ? t("Wird geprüft …") : t("Fortfahren")}
                    </button>
                </form>
            )}
            {pending && (
                <button
                    className="text-button"
                    onClick={() => {
                        setRecovery(!recovery);
                        setCode("");
                    }}
                >
                    {recovery
                        ? t("Authenticator verwenden")
                        : t("Wiederherstellungscode verwenden")}
                </button>
            )}
            <p className="muted">
                {t("Geschützter Zugang · Verbindung über HTTPS")}
            </p>
        </main>
    );
}
