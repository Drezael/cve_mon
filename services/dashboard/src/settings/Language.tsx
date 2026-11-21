import { useEffect, useState } from "react";
import { api } from "../api";
import { useData, State } from "../ui";
import {
    t,
    useLocale,
    setLocale,
    translateMessage,
    type Locale,
} from "../i18n";
import {
    PERSONAL_LOCALE,
    INSTANCE_LOCALE,
    LOCALE_UPDATED,
    announceLocaleChange,
    instanceSchema,
    personalSchema,
} from "./localization";

export function LanguageSettings() {
    useLocale();
    const result = useData(PERSONAL_LOCALE, personalSchema, {
        refreshEvent: LOCALE_UPDATED,
    });
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [saved, setSaved] = useState(false);
    const [value, setValue] = useState<Locale | null>(null);
    const [version, setVersion] = useState(0);
    useEffect(() => {
        if (result.data) {
            setValue(result.data.locale);
            setVersion(result.data.version);
        }
    }, [result.data]);
    async function change(locale: Locale | null) {
        if (busy || !result.data) return;
        setBusy(true);
        setError("");
        setSaved(false);
        try {
            const response = await api(PERSONAL_LOCALE, personalSchema, {
                method: "PUT",
                version,
                body: { locale },
            });
            setValue(response.locale);
            setVersion(response.version);
            setLocale(response.effective_locale);
            setSaved(true);
            announceLocaleChange();
        } catch (e) {
            setError(
                e instanceof Error ? e.message : t("Speichern fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    return (
        <section>
            <h1>{t("Sprache")}</h1>
            <p>
                {t(
                    "Die Sprache wird in deinem Konto gespeichert und gilt auf allen Geräten. Der Wechsel erfolgt ohne Neuladen.",
                )}
            </p>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <label>
                        {t("Sprache")}
                        <select
                            aria-label={t("Sprache")}
                            value={value ?? ""}
                            disabled={busy}
                            onChange={(e) =>
                                void change(
                                    e.target.value === ""
                                        ? null
                                        : (e.target.value as Locale),
                                )
                            }
                        >
                            <option value="">
                                {t("Instanzstandard verwenden")}
                            </option>
                            <LanguageOptions />
                        </select>
                    </label>
                    <p className="muted">
                        {t("Aktueller Instanzstandard:")}{" "}
                        {result.data.default_locale === "de"
                            ? "Deutsch"
                            : "English"}
                    </p>
                    {busy && <p role="status">{t("Wird gespeichert …")}</p>}
                    {saved && (
                        <p role="status">
                            {t("Sprache im Konto gespeichert.")}
                        </p>
                    )}
                </>
            )}
            {error && (
                <p role="alert">
                    {translateMessage(error)}{" "}
                    <button onClick={result.reload}>
                        {t("Aktuellen Stand neu laden")}
                    </button>
                </p>
            )}
        </section>
    );
}
export function InstanceLanguageSettings() {
    useLocale();
    const result = useData(INSTANCE_LOCALE, instanceSchema);
    const [value, setValue] = useState<Locale>("en");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [saved, setSaved] = useState(false);
    useEffect(() => {
        if (result.data) setValue(result.data.default_locale);
    }, [result.data]);
    async function save() {
        if (!result.data || busy) return;
        setBusy(true);
        setError("");
        setSaved(false);
        try {
            await api(INSTANCE_LOCALE, instanceSchema, {
                method: "PUT",
                version: result.data.version,
                body: { default_locale: value },
            });
            setSaved(true);
            result.reload();
            window.dispatchEvent(new Event(LOCALE_UPDATED));
            announceLocaleChange();
        } catch (e) {
            setError(
                e instanceof Error ? e.message : t("Speichern fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    return (
        <section>
            <h1>{t("Instanzeinstellungen")}</h1>
            <h2>{t("Standardsprache")}</h2>
            <p>
                {t(
                    "Gilt vor der Anmeldung und für Konten ohne eigene Sprachauswahl. Bereits gespeicherte Kontosprachen bleiben erhalten.",
                )}
            </p>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        void save();
                    }}
                >
                    <label>
                        {t("Standardsprache")}
                        <select
                            aria-label={t("Standardsprache")}
                            value={value}
                            disabled={busy}
                            onChange={(e) => setValue(e.target.value as Locale)}
                        >
                            <LanguageOptions />
                        </select>
                    </label>
                    <button disabled={busy} type="submit">
                        {busy
                            ? t("Wird gespeichert …")
                            : t("Standardsprache speichern")}
                    </button>
                </form>
            )}
            {error && (
                <p role="alert">
                    {translateMessage(error)}{" "}
                    <button onClick={result.reload}>
                        {t("Aktuellen Stand neu laden")}
                    </button>
                </p>
            )}
            {saved && <p role="status">{t("Standardsprache gespeichert.")}</p>}
        </section>
    );
}
function LanguageOptions() {
    return (
        <>
            <option value="de" lang="de">
                Deutsch
            </option>
            <option value="en" lang="en">
                English
            </option>
        </>
    );
}
