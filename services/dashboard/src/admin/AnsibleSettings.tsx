import { translateMessage, t, useLocale } from "../i18n";
import { useEffect, useState, type FormEvent } from "react";
import { z } from "zod";
import { api } from "../api";
import { Card, State, useData } from "../ui";
import { date } from "../format";

const profileSchema = z.object({
    version: z.number(),
    host: z.string(),
    port: z.number(),
    username: z.string(),
    auth_method: z.enum(["key", "password"]),
    use_sudo: z.boolean().transform(() => false),
    enabled: z.boolean(),
    interval_seconds: z.number(),
    next_due: z.string().nullable(),
    host_key: z.string().nullable(),
    host_key_confirmed: z.boolean(),
    mount_paths: z.array(z.string()),
});
const schema = z.object({
    profile: profileSchema.nullable(),
    credentials_configured: z.boolean(),
    runs: z.array(
        z.object({
            id: z.string(),
            profile_version: z.number(),
            fingerprint: z.string().nullable(),
            action: z.string(),
            state: z.string(),
            requested_at: z.string(),
            finished_at: z.string().nullable(),
            error_code: z.string().nullable(),
            host_key: z.string().nullable(),
            execution_id: z.string().nullable(),
        }),
    ),
});
type Profile = z.infer<typeof profileSchema>;
const defaults: Profile = {
    version: 1,
    host: "",
    port: 22,
    username: "",
    auth_method: "key",
    use_sudo: false,
    enabled: false,
    interval_seconds: 21600,
    next_due: null,
    host_key: null,
    host_key_confirmed: false,
    mount_paths: [],
};

function ConnectionForm({
    server,
    profile,
    reload,
}: {
    server: string;
    profile: Profile | null;
    reload: () => void;
}) {
    useLocale();
    const [value, setValue] = useState(profile ?? defaults);
    const [secrets, setSecrets] = useState({
        private_key: "",
        password: "",
        passphrase: "",
        sudo_password: "",
    });
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    async function save(e: FormEvent) {
        e.preventDefault();
        setBusy(true);
        setError("");
        try {
            const connection = Object.fromEntries(
                Object.entries(value).filter(
                    ([key]) =>
                        ![
                            "version",
                            "next_due",
                            "host_key",
                            "host_key_confirmed",
                        ].includes(key),
                ),
            );
            await api(
                `/api/v1/dashboard/servers/${server}/ansible`,
                z.unknown(),
                {
                    method: "PUT",
                    body: {
                        ...connection,
                        ...Object.fromEntries(
                            Object.entries(secrets).filter(([, v]) => v !== ""),
                        ),
                    },
                },
            );
            setSecrets({
                private_key: "",
                password: "",
                passphrase: "",
                sudo_password: "",
            });
            reload();
        } catch (e) {
            setError(
                e instanceof Error ? e.message : t("Speichern fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    function secret(
        key: keyof typeof secrets,
        label: string,
        multiline = false,
    ) {
        return (
            <label>
                {label}
                {multiline ? (
                    <textarea
                        autoComplete="off"
                        value={secrets[key]}
                        onChange={(e) =>
                            setSecrets({ ...secrets, [key]: e.target.value })
                        }
                        maxLength={32768}
                    />
                ) : (
                    <input
                        type="password"
                        autoComplete="new-password"
                        value={secrets[key]}
                        onChange={(e) =>
                            setSecrets({ ...secrets, [key]: e.target.value })
                        }
                        maxLength={32768}
                    />
                )}
            </label>
        );
    }
    return (
        <form onSubmit={(e) => void save(e)}>
            <p>
                {t(
                    "Die Erfassung läuft über n8n. Zugangsdaten werden verschlüsselt gespeichert. Leere Geheimnisfelder behalten gespeicherte Werte bei.",
                )}
            </p>
            <div className="filters">
                <label>
                    {t("Hostname oder IP")}
                    <input
                        required
                        value={value.host}
                        maxLength={253}
                        onChange={(e) =>
                            setValue({ ...value, host: e.target.value })
                        }
                    />
                </label>
                <label>
                    {t("SSH-Port")}
                    <input
                        required
                        type="number"
                        min={1}
                        max={65535}
                        value={value.port}
                        onChange={(e) =>
                            setValue({ ...value, port: Number(e.target.value) })
                        }
                    />
                </label>
                <label>
                    {t("SSH-Benutzer")}
                    <input
                        required
                        value={value.username}
                        maxLength={64}
                        onChange={(e) =>
                            setValue({ ...value, username: e.target.value })
                        }
                    />
                </label>
                <label>
                    {t("Anmeldung")}
                    <select
                        value={value.auth_method}
                        onChange={(e) =>
                            setValue({
                                ...value,
                                auth_method: e.target.value as
                                    "key" | "password",
                            })
                        }
                    >
                        <option value="key">{t("SSH-Schlüssel")}</option>
                        <option value="password">{t("Passwort")}</option>
                    </select>
                </label>
            </div>
            {value.auth_method === "key" ? (
                <>
                    {secret("private_key", t("Privater SSH-Schlüssel"), true)}
                    {secret("passphrase", t("Schlüssel-Passphrase"))}
                </>
            ) : (
                secret("password", "SSH-Passwort")
            )}
            <p>
                {t(
                    "Die Inventarisierung erfolgt ohne sudo und ausschließlich lesend.",
                )}
            </p>
            <label>
                <input
                    type="checkbox"
                    checked={value.enabled}
                    onChange={(e) =>
                        setValue({ ...value, enabled: e.target.checked })
                    }
                />{" "}
                {t("Regelmäßig erfassen")}
            </label>
            <label>
                {t("Abfrageintervall in Minuten")}
                <input
                    required
                    type="number"
                    min={5}
                    max={10080}
                    value={value.interval_seconds / 60}
                    onChange={(e) =>
                        setValue({
                            ...value,
                            interval_seconds: Number(e.target.value) * 60,
                        })
                    }
                />
            </label>
            <label>
                {t(
                    "Zusätzliche Anwendungsverzeichnisse in Container-Mounts (ein Pfad pro Zeile)",
                )}
                <textarea
                    value={value.mount_paths.join("\n")}
                    onChange={(e) =>
                        setValue({
                            ...value,
                            mount_paths: e.target.value
                                .split("\n")
                                .filter(Boolean),
                        })
                    }
                />
            </label>
            {error && <p role="alert">{translateMessage(error)}</p>}
            <button disabled={busy}>
                {busy ? t("Speichert …") : t("Verbindung speichern")}
            </button>
        </form>
    );
}

export default function AnsibleSettings({ server }: { server: string }) {
    useLocale();
    const path = `/api/v1/dashboard/servers/${server}/ansible`;
    const result = useData(path, schema);
    const [busy, setBusy] = useState(false);
    const [notice, setNotice] = useState("");
    const pending = result.data?.runs.some((r) =>
        ["pending", "queued", "running", "retry", "retry_wait"].includes(
            r.state,
        ),
    );
    const reload = result.reload;
    useEffect(() => {
        if (!pending) return;
        const timer = setTimeout(reload, 3000);
        return () => clearTimeout(timer);
    }, [pending, reload]);
    async function action(name: string, body?: unknown) {
        setBusy(true);
        setNotice("");
        try {
            await api(`${path}/${name}`, z.unknown(), { method: "POST", body });
            setNotice(
                name === "confirm-key"
                    ? t("Hostkey bestätigt.")
                    : t("Lauf bei n8n angefordert."),
            );
            result.reload();
        } catch (e) {
            setNotice(
                e instanceof Error ? e.message : t("Aktion fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    async function confirm(key: string) {
        const bytes = Uint8Array.from(atob(key.split(" ").at(-1)!), (c) =>
            c.charCodeAt(0),
        );
        const hash = new Uint8Array(
            await crypto.subtle.digest("SHA-256", bytes),
        );
        const fingerprint =
            "SHA256:" + btoa(String.fromCharCode(...hash)).replace(/=+$/, "");
        await action("confirm-key", { fingerprint });
    }
    const data = result.data;
    const probe = data?.runs.find(
        (r) =>
            r.action === "probe" &&
            r.state === "succeeded" &&
            r.host_key &&
            r.profile_version === data?.profile?.version,
    );
    return (
        <Card title={t("Automatische Erfassung mit Ansible")}>
            {!data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <ConnectionForm
                        server={server}
                        profile={data.profile}
                        reload={result.reload}
                    />
                    {data.profile && (
                        <>
                            <p>
                                {t("Hostkey:")}{" "}
                                {data.profile.host_key_confirmed
                                    ? t("bestätigt")
                                    : t("noch nicht bestätigt")}
                                {t(". Nächste Erfassung:")}{" "}
                                {data.profile.enabled &&
                                data.profile.host_key_confirmed
                                    ? date(data.profile.next_due)
                                    : "deaktiviert"}
                                .
                            </p>
                            <div className="actions">
                                <button
                                    disabled={busy || pending}
                                    onClick={() => void action("probe")}
                                >
                                    {t("Hostkey auslesen")}
                                </button>
                                <button
                                    disabled={
                                        busy ||
                                        pending ||
                                        !data.profile.host_key_confirmed
                                    }
                                    onClick={() => void action("test")}
                                >
                                    {t("Verbindung testen")}
                                </button>
                                <button
                                    disabled={
                                        busy ||
                                        pending ||
                                        !data.profile.host_key_confirmed
                                    }
                                    onClick={() => void action("collect")}
                                >
                                    {t("Jetzt erfassen")}
                                </button>
                            </div>
                            {probe?.host_key &&
                                !data.profile.host_key_confirmed && (
                                    <div className="notice">
                                        <p>
                                            {t(
                                                "Vergleichen Sie diesen öffentlichen Schlüssel mit dem Zielserver, bevor Sie ihn bestätigen:",
                                            )}
                                        </p>
                                        <p>
                                            <code>{probe.fingerprint}</code>
                                        </p>
                                        <details>
                                            <summary>
                                                {t(
                                                    "Öffentlicher SSH-Schlüssel",
                                                )}
                                            </summary>
                                            <code>{probe.host_key}</code>
                                        </details>
                                        <button
                                            disabled={busy}
                                            onClick={() =>
                                                void confirm(probe.host_key!)
                                            }
                                        >
                                            {t("Hostkey bestätigen")}
                                        </button>
                                    </div>
                                )}
                        </>
                    )}
                    <h3>{t("Letzte Läufe")}</h3>
                    {data.runs.length === 0 ? (
                        <p>{t("Noch keine Läufe.")}</p>
                    ) : (
                        <div className="table-scroll">
                            <table>
                                <thead>
                                    <tr>
                                        <th>{t("Angefordert")}</th>
                                        <th>{t("Aktion")}</th>
                                        <th>{t("Status")}</th>
                                        <th>{t("Fehler")}</th>
                                        <th>{t("n8n-Ausführung")}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {data.runs.map((r) => (
                                        <tr key={r.id}>
                                            <td>{date(r.requested_at)}</td>
                                            <td>
                                                {{
                                                    probe: t(
                                                        "Hostkey auslesen",
                                                    ),
                                                    test: t(
                                                        "Verbindung testen",
                                                    ),
                                                    collect:
                                                        t("Inventar erfassen"),
                                                }[r.action] ?? r.action}
                                            </td>
                                            <td>{r.state}</td>
                                            <td>{r.error_code ?? "—"}</td>
                                            <td>{r.execution_id ?? "—"}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </>
            )}
            {notice && <p role="status">{translateMessage(notice)}</p>}
        </Card>
    );
}
