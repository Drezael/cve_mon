import { translateMessage, t, useLocale } from "../i18n";
import { useState } from "react";
import { useAuth } from "../auth";
import { useData, State, Card, Facts, Pagination } from "../ui";
import { row, listing } from "./contracts";
import { EditForm, type Mutation } from "./Form";
import { MfaSettings } from "./MfaSettings";
import { auditFacts } from "./audit";
export function Account() {
    useLocale();
    const { refresh, setEnrollmentSecret } = useAuth();
    const session = useData("/api/v1/auth/session", row);
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [notice, setNotice] = useState("");
    return (
        <>
            <h1>{t("Kontosicherheit")}</h1>
            {notice && <p role="status">{translateMessage(notice)}</p>}
            {session.data ? (
                <Card title={t("Eigene Sitzung")}>
                    <Facts values={session.data} />
                    <div className="actions">
                        <button
                            onClick={() =>
                                setOperation({
                                    title: t("Eigenes Passwort ändern"),
                                    path: "/api/v1/auth/password/change",
                                    method: "POST",
                                    stepUp: false,
                                    critical: true,
                                    fields: [
                                        {
                                            key: "password",
                                            label: t("Aktuelles Passwort"),
                                            type: "password",
                                            required: true,
                                            max: 256,
                                        },
                                        {
                                            key: "new_password",
                                            label: t("Neues Passwort"),
                                            type: "password",
                                            required: true,
                                            min: 15,
                                            max: 256,
                                        },
                                        {
                                            key: "code",
                                            label: t(
                                                "MFA-Code, falls eingerichtet",
                                            ),
                                            max: 6,
                                        },
                                    ],
                                    payload: (v) => ({
                                        password: v.password,
                                        new_password: v.new_password,
                                        ...(v.code ? { code: v.code } : {}),
                                    }),
                                })
                            }
                        >
                            {t("Passwort ändern")}
                        </button>
                        <button
                            onClick={() =>
                                setOperation({
                                    title: t("Alle eigenen Sitzungen abmelden"),
                                    path: "/api/v1/auth/logout-all",
                                    method: "POST",
                                    critical: true,
                                    stepUp: false,
                                    fields: [],
                                    initial: {},
                                })
                            }
                        >
                            {t("Alle eigenen Sitzungen abmelden")}
                        </button>
                        <button
                            onClick={() =>
                                setOperation({
                                    title: t(
                                        "Genehmigte MFA-Wiederherstellung einlösen",
                                    ),
                                    path: "/api/v1/auth/mfa/recovery/redeem",
                                    method: "POST",
                                    stepUp: false,
                                    fields: [
                                        {
                                            key: "recovery_token",
                                            label: t(
                                                "Sicher übergebener Wiederherstellungsauftrag",
                                            ),
                                            type: "password",
                                            required: true,
                                            min: 70,
                                            max: 100,
                                        },
                                    ],
                                })
                            }
                        >
                            {t("MFA-Wiederherstellungsauftrag einlösen")}
                        </button>
                    </div>
                    <p>
                        {t(
                            "Es werden keine Passwörter, gespeicherten MFA-Schlüssel oder technischen Tokens angezeigt. Passwortänderungen und Wiederherstellung folgen ausschließlich den vorhandenen serverseitigen Kontoregeln.",
                        )}
                    </p>
                </Card>
            ) : (
                <State error={session.error} reload={session.reload} />
            )}
            {session.data && (
                <MfaSettings
                    enabled={session.data.mfa_enabled === true}
                    reload={session.reload}
                />
            )}
            {operation && (
                <EditForm
                    operation={operation}
                    onCancel={() => setOperation(null)}
                    onReload={() => {
                        setOperation(null);
                        session.reload();
                    }}
                    onDone={(r) => {
                        if (typeof r?.provisioning_uri === "string")
                            setEnrollmentSecret(
                                new URL(r.provisioning_uri).searchParams.get(
                                    "secret",
                                ),
                            );
                        setOperation(null);
                        setNotice(t("Kontovorgang bestätigt."));
                        session.reload();
                        void refresh(true);
                    }}
                />
            )}
        </>
    );
}
export function Activation() {
    useLocale();
    const [done, setDone] = useState(false);
    return (
        <main className="auth">
            <h1>{t("Konto aktivieren")}</h1>
            {done ? (
                <>
                    <p role="status">{t("Kontoaktivierung bestätigt.")}</p>
                    <a href="/login">{t("Zur Anmeldung")}</a>
                </>
            ) : (
                <EditForm
                    operation={{
                        title: t("Sicheren Aktivierungsauftrag einlösen"),
                        path: "/api/v1/auth/activation/redeem",
                        method: "POST",
                        stepUp: false,
                        fields: [
                            {
                                key: "activation_token",
                                label: t(
                                    "Sicher übergebener Aktivierungsauftrag",
                                ),
                                type: "password",
                                required: true,
                                min: 70,
                                max: 100,
                            },
                            {
                                key: "new_password",
                                label: t("Eigenes neues Passwort"),
                                type: "password",
                                required: true,
                                min: 15,
                                max: 256,
                            },
                        ],
                    }}
                    onCancel={() => window.location.assign("/login")}
                    onReload={() => window.location.reload()}
                    onDone={() => setDone(true)}
                />
            )}
        </main>
    );
}
export function Audit() {
    useLocale();
    const [search, setSearch] = useState("");
    const [query, setQuery] = useState("");
    const [offset, setOffset] = useState(0);
    const result = useData(
        "/api/v1/dashboard/administration/audit?" +
            new URLSearchParams({
                action: query,
                limit: "25",
                offset: String(offset),
            }),
        listing,
    );
    return (
        <>
            <h1>{t("Änderungsverlauf")}</h1>
            <p>
                {t(
                    "Unveränderliche Audit-Metadaten. Administratoren sehen die zugelassenen Fachereignisse; andere Auditberechtigte ausschließlich eigene Akteursereignisse. Geheimnisse und rohe Nutzdaten werden nicht ausgegeben.",
                )}
            </p>
            <div className="filters">
                <label>
                    {t("Aktion filtern")}
                    <input
                        value={search}
                        maxLength={128}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </label>
                <button
                    onClick={() => {
                        setQuery(search);
                        setOffset(0);
                    }}
                >
                    {t("Filtern")}
                </button>
            </div>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <Card title={t("Auditereignisse")}>
                    {result.data.items.length === 0 && (
                        <p>{t("Keine berechtigten Ereignisse.")}</p>
                    )}
                    {result.data.items.map((r) => (
                        <article className="record" key={String(r.id)}>
                            <Facts values={auditFacts(r)} />
                        </article>
                    ))}
                    <Pagination
                        offset={offset}
                        total={result.data.total}
                        onChange={setOffset}
                    />
                </Card>
            )}
        </>
    );
}
