import { translateMessage, t, useLocale } from "../i18n";
import { useEffect, useRef, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { z } from "zod";
import { api, ApiError, authResult } from "../api";
import { useData, State, Card, Facts } from "../ui";
import {
    listing,
    row,
    itemList,
    serverCreateSchema,
    type Row,
} from "./contracts";
import { DraftGuard, Inputs, Modal } from "./Form";
import { serverFields } from "./serverFields";
import InventoryFields from "../InventoryFields";
type InventoryDraft = { raw: string; value: Row };
const configuration = listing.extend({
    max_bytes: z.number(),
    schema_versions: z.array(z.string()),
});
export default function Upload({
    manualAllowed = false,
}: {
    manualAllowed?: boolean;
}) {
    useLocale();
    const config = useData(
        "/api/v1/dashboard/administration/upload-options",
        configuration,
    );
    const [params] = useSearchParams();
    const navigate = useNavigate();
    const submission = params.get("submission");
    const [server, setServer] = useState("");
    const [file, setFile] = useState<File | null>(null);
    const [draft, setDraft] = useState<InventoryDraft | null>(null);
    const [reading, setReading] = useState(false);
    const [metadata, setMetadata] = useState<Row>({
        criticality: "medium",
        exposure: "unknown",
    });
    const [metadataDirty, setMetadataDirty] = useState(false);
    const edited = useRef(new Set<string>());
    const manualRequest = useRef(crypto.randomUUID());
    const [reauthenticate, setReauthenticate] = useState(false);
    const [password, setPassword] = useState("");
    const [code, setCode] = useState("");
    const readRevision = useRef(0);
    const controller = useRef(new AbortController());
    const fileInput = useRef<HTMLInputElement>(null);
    useEffect(() => {
        const active = new AbortController();
        controller.current = active;
        return () => active.abort();
    }, []);
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    const [uncertain, setUncertain] = useState(false);
    const [receipt, setReceipt] = useState<Row | null>(null);
    const [status, setStatus] = useState<Row | null>(null);
    const request = useRef(crypto.randomUUID());
    const inventoryId = useRef("");
    const running = useRef(false);
    const [poll, setPoll] = useState(true);
    const [reload, setReload] = useState(0);
    useEffect(() => {
        if (!submission) return;
        const c = new AbortController();
        let count = 0;
        let timer: ReturnType<typeof setTimeout> | undefined;
        async function check() {
            try {
                const result = await api(
                    "/api/v1/dashboard/administration/uploads/" + submission,
                    row,
                    { signal: c.signal },
                );
                setStatus(result);
                const processing = result.processing as Row;
                if (
                    poll &&
                    ["accepted", "processing"].includes(
                        String(processing.status),
                    ) &&
                    ++count < 12
                )
                    timer = setTimeout(() => void check(), 5000);
            } catch (e) {
                if (!c.signal.aborted)
                    setError(
                        e instanceof Error
                            ? e.message
                            : t("Status nicht verfügbar."),
                    );
            }
        }
        void check();
        return () => {
            c.abort();
            if (timer) clearTimeout(timer);
        };
    }, [submission, poll, reload]);
    function discard() {
        readRevision.current++;
        if (fileInput.current) fileInput.current.value = "";
        setFile(null);
        setDraft(null);
        setReading(false);
    }
    async function loadFile(selected: File | null) {
        const revision = ++readRevision.current;
        setFile(selected);
        setDraft(null);
        setError("");
        setReading(!!selected);
        request.current = crypto.randomUUID();
        if (!selected || !config.data) {
            setReading(false);
            return;
        }
        try {
            const file = selected;
            if (file.size === 0 || file.size > config.data.max_bytes)
                throw new Error(
                    t(
                        "Die Datei ist leer oder überschreitet die zulässige Größe.",
                    ),
                );
            if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/i.test(file.name))
                throw new Error(
                    t(
                        "Eine JSON-Datei mit einfachem Dateinamen ist erforderlich.",
                    ),
                );
            const raw = new TextDecoder("utf-8", { fatal: true }).decode(
                await file.arrayBuffer(),
            );
            const value = JSON.parse(raw) as Row;
            if (
                !config.data.schema_versions.includes(
                    String(value.schema_version),
                )
            )
                throw new Error(t("Nicht unterstützte Schema-Version."));
            if (
                !value ||
                typeof value !== "object" ||
                Array.isArray(value) ||
                !z.string().uuid().safeParse(value.inventory_id).success ||
                !value.host ||
                typeof value.host !== "object" ||
                Array.isArray(value.host) ||
                !z
                    .string()
                    .min(1)
                    .safeParse((value.host as Row).hostname).success
            )
                throw new Error(
                    t(
                        "Das Inventar muss eine gültige Inventar-ID und Hostdaten mit Hostname enthalten.",
                    ),
                );
            if (
                revision === readRevision.current &&
                !controller.current.signal.aborted
            ) {
                setDraft({ raw, value });
                setMetadata((old) => ({
                    ...old,
                    display_name:
                        edited.current.has("display_name") && old.display_name
                            ? old.display_name
                            : (value.host as Row).hostname,
                }));
                setMetadataDirty(true);
            }
        } catch (e) {
            if (
                revision === readRevision.current &&
                !controller.current.signal.aborted
            )
                setError(
                    e instanceof SyntaxError || e instanceof TypeError
                        ? t("Die Datei muss gültiges UTF-8 und JSON enthalten.")
                        : e instanceof Error
                          ? e.message
                          : t("Inventar konnte nicht geladen werden."),
                );
        } finally {
            if (
                revision === readRevision.current &&
                !controller.current.signal.aborted
            )
                setReading(false);
        }
    }
    function details() {
        const parsed = serverCreateSchema.parse({
            request_id: manualRequest.current,
            ...metadata,
            description: metadata.description || null,
            environment: metadata.environment || null,
        });
        return {
            display_name: parsed.display_name,
            description: parsed.description,
            environment: parsed.environment,
            criticality: parsed.criticality,
            exposure: parsed.exposure,
        };
    }
    function editMetadata(key: string, value: unknown) {
        edited.current.add(key);
        setMetadataDirty(true);
        setMetadata((old) => ({ ...old, [key]: value }));
    }
    async function saveManual() {
        if (!manualAllowed || file || running.current || reading) return;
        running.current = true;
        setBusy(true);
        setError("");
        let sent = false;
        try {
            const value = details();
            await api("/api/v1/auth/reauthenticate", authResult, {
                signal: controller.current.signal,
                method: "POST",
                body: { password, ...(code ? { code } : {}) },
            });
            sent = true;
            await api(
                "/api/v1/dashboard/admin/servers",
                row.extend({ id: z.string().uuid() }),
                {
                    signal: controller.current.signal,
                    method: "POST",
                    body: { ...value, request_id: manualRequest.current },
                },
            );
            setMetadataDirty(false);
            setReauthenticate(false);
            navigate("/servers", { replace: true });
        } catch (problem) {
            if (controller.current.signal.aborted) return;
            setError(
                problem instanceof z.ZodError
                    ? t("Bitte die Server-Stammdaten prüfen.")
                    : problem instanceof Error
                      ? problem.message
                      : t("Server konnte nicht gespeichert werden."),
            );
            setReauthenticate(false);
            if (
                sent &&
                problem instanceof ApiError &&
                [0, 502, 503, 504].includes(problem.status)
            )
                setUncertain(true);
        } finally {
            setPassword("");
            setCode("");
            running.current = false;
            setBusy(false);
        }
    }
    function save() {
        if (file) {
            void submit();
            return;
        }
        if (!manualAllowed) return;
        try {
            details();
            setError("");
            setReauthenticate(true);
        } catch {
            setError(t("Bitte die Server-Stammdaten prüfen."));
        }
    }
    async function submit() {
        if (
            running.current ||
            !file ||
            !draft ||
            reading ||
            !config.data ||
            uncertain
        )
            return;
        running.current = true;
        setBusy(true);
        setError("");
        try {
            const value = draft.value;
            const serverDetails = details();
            if (
                server &&
                value.server_id &&
                String(value.server_id).toLowerCase() !== server.toLowerCase()
            )
                throw new Error(
                    t(
                        "Server-UUID in Datei und Auswahl stimmen nicht überein.",
                    ),
                );
            inventoryId.current = String(value.inventory_id);
            const body = new FormData();
            if (server) body.set("server_id", server);
            body.set("server_metadata", JSON.stringify(serverDetails));
            body.set(
                "file",
                new Blob([draft.raw], { type: "application/json" }),
                file.name,
            );
            const result = await api(
                "/api/v1/dashboard/inventories/upload",
                row,
                { method: "POST", body, idempotencyKey: request.current },
            );
            setReceipt(result);
            setMetadataDirty(false);
            discard();
            navigate("/servers", { replace: true });
        } catch (e) {
            setError(
                e instanceof ApiError && e.status === 409
                    ? t(
                          "Die Serverkennung oder Inventar-ID widerspricht vorhandenen Daten. Bitte die Zuordnung prüfen; es wurde kein neuer Server angelegt.",
                      )
                    : e instanceof z.ZodError
                      ? t("Bitte die Server-Stammdaten prüfen.")
                      : e instanceof SyntaxError || e instanceof TypeError
                        ? t("Die Datei muss gültiges UTF-8 und JSON enthalten.")
                        : e instanceof Error
                          ? e.message
                          : t("Upload abgewiesen."),
            );
            if (e instanceof ApiError && [0, 502, 503, 504].includes(e.status))
                setUncertain(true);
        } finally {
            running.current = false;
            setBusy(false);
        }
    }
    async function reconcile() {
        setBusy(true);
        try {
            const existing = await api(
                "/api/v1/dashboard/administration/uploads?inventory_id=" +
                    encodeURIComponent(inventoryId.current),
                itemList,
            );
            if (existing.items.length) {
                setUncertain(false);
                setMetadataDirty(false);
                discard();
                navigate("/servers", { replace: true });
            } else {
                setError(
                    t(
                        "Noch keine Annahme gefunden. Eine ausdrückliche Wiederholung verwendet dieselbe Idempotenz-ID und dieselbe Datei.",
                    ),
                );
                setUncertain(false);
            }
        } catch (e) {
            setError(
                e instanceof Error
                    ? e.message
                    : t("Statusprüfung fehlgeschlagen."),
            );
        } finally {
            setBusy(false);
        }
    }
    return (
        <>
            <h1>{t("Server anlegen")}</h1>
            <DraftGuard
                dirty={(file !== null || metadataDirty) && !busy}
                onDiscard={() => {
                    discard();
                    setMetadataDirty(false);
                }}
            />
            <p>
                {t(
                    "Tragen Sie die Serverdaten ein oder laden Sie optional ein Serverinventar, um die Maske vorauszufüllen. Erst „Server speichern“ übernimmt die Daten.",
                )}
            </p>

            {error && (
                <div role="alert" className="notice">
                    {translateMessage(error)}
                </div>
            )}
            {!config.data ? (
                <State error={config.error} reload={config.reload} />
            ) : (
                <Card title={t("Serverdaten")}>
                    <fieldset disabled={busy || uncertain}>
                        <section
                            className="server-form-grid"
                            aria-label={t("Server-Stammdaten")}
                        >
                            <Inputs
                                fields={serverFields}
                                values={metadata}
                                set={editMetadata}
                            />
                        </section>
                        <h2>{t("Serverinventar laden (optional)")}</h2>
                        <details>
                            <summary>
                                {t("Informationen zum Inventarformat")}
                            </summary>{" "}
                            <p>
                                {t("Maximal")} {config.data.max_bytes}{" "}
                                {t("Bytes. Kanonischer Vertrag:")}{" "}
                                {config.data.schema_versions.map((v) => (
                                    <a
                                        key={v}
                                        href={
                                            "/api/v1/dashboard/administration/inventory-schema/" +
                                            v
                                        }
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        {" "}
                                        {t("Schema")} {v}{" "}
                                    </a>
                                ))}
                                {t(". Die Datei wird vor der Annahme geprüft.")}
                            </p>
                        </details>
                        <details>
                            <summary>
                                {t("Vorhandenem Server zuordnen (optional)")}
                            </summary>
                            <p>
                                {t(
                                    "Für die erstmalige Zuordnung einer neuen Monitoring-ID zu einem bereits registrierten Server.",
                                )}
                            </p>
                            <Inputs
                                fields={[
                                    {
                                        key: "server",
                                        label: t("Vorhandener Server"),
                                        type: "picker",
                                        source: "/api/v1/dashboard/administration/upload-options",
                                    },
                                ]}
                                values={{ server }}
                                set={(_, v) => setServer(String(v ?? ""))}
                            />
                        </details>
                        <label>
                            {t("JSON-Datei")}
                            <input
                                ref={fileInput}
                                type="file"
                                accept=".json,application/json"
                                onChange={(e) =>
                                    void loadFile(e.target.files?.[0] ?? null)
                                }
                            />
                        </label>
                        {file && (
                            <p>
                                {file.name} · {file.size} {t("Bytes")}
                            </p>
                        )}
                        {reading && (
                            <p role="status">
                                {t("Inventardatei wird vollständig geladen …")}
                            </p>
                        )}
                        {draft && (
                            <>
                                <InventoryPreview draft={draft} />
                                <InventoryFields
                                    value={draft.value}
                                    onChange={(value) =>
                                        setDraft({
                                            value,
                                            raw: JSON.stringify(value, null, 2),
                                        })
                                    }
                                />
                            </>
                        )}
                        {file && (
                            <button onClick={discard}>
                                {t("Inventar verwerfen")}
                            </button>
                        )}
                        <div className="actions server-form-actions">
                            <button
                                type="button"
                                disabled={busy}
                                onClick={() => navigate("/servers")}
                            >
                                {t("Abbrechen")}
                            </button>
                            <button
                                disabled={
                                    reading ||
                                    busy ||
                                    !!submission ||
                                    (file
                                        ? !draft
                                        : !manualAllowed ||
                                          !String(
                                              metadata.display_name ?? "",
                                          ).trim())
                                }
                                onClick={save}
                            >
                                {busy
                                    ? t(
                                          "Übertragung und Annahme werden geprüft …",
                                      )
                                    : t("Server speichern")}
                            </button>
                        </div>
                    </fieldset>
                    {busy && (
                        <p role="status">
                            {t(
                                "Übertragung läuft. Ein Abschluss wird erst nach bestätigter Annahme angezeigt.",
                            )}
                        </p>
                    )}
                    {uncertain && (
                        <>
                            <p>
                                {t(
                                    "Ergebnis unbekannt. Es wurde keine automatische Wiederholung ausgelöst.",
                                )}
                            </p>
                            <button
                                disabled={busy}
                                onClick={() => {
                                    if (file) void reconcile();
                                    else save();
                                }}
                            >
                                {file
                                    ? t("Annahme anhand der Inventar-ID prüfen")
                                    : t("Dieselbe Anfrage erneut prüfen")}
                            </button>
                        </>
                    )}
                </Card>
            )}
            {reauthenticate && (
                <Modal
                    title={t("Identität erneut bestätigen")}
                    onCancel={() => {
                        if (!busy) {
                            setReauthenticate(false);
                            setPassword("");
                            setCode("");
                        }
                    }}
                >
                    <form
                        onSubmit={(event) => {
                            event.preventDefault();
                            void saveManual();
                        }}
                    >
                        <fieldset disabled={busy}>
                            <label>
                                {t("Aktuelles Passwort")}
                                <input
                                    type="password"
                                    autoComplete="current-password"
                                    required
                                    maxLength={256}
                                    value={password}
                                    onChange={(event) =>
                                        setPassword(event.target.value)
                                    }
                                />
                            </label>
                            <label>
                                {t("MFA-Code, falls eingerichtet")}
                                <input
                                    autoComplete="one-time-code"
                                    inputMode="numeric"
                                    pattern="[0-9]{6}"
                                    maxLength={6}
                                    value={code}
                                    onChange={(event) =>
                                        setCode(event.target.value)
                                    }
                                />
                            </label>
                            <button
                                type="button"
                                onClick={() => {
                                    setReauthenticate(false);
                                    setPassword("");
                                    setCode("");
                                }}
                            >
                                {t("Abbrechen")}
                            </button>
                            <button type="submit">
                                {t("Identität bestätigen und speichern")}
                            </button>
                        </fieldset>
                    </form>
                </Modal>
            )}
            {receipt && (
                <Card title={t("Inventar angenommen")}>
                    <p>
                        {t(
                            "Der Server wurde zugeordnet. Inventar und Schwachstellen werden im Hintergrund geprüft.",
                        )}
                    </p>
                    <Facts values={receipt} />
                </Card>
            )}
            {submission && (
                <Card title={t("Verarbeitungsstatus")}>
                    <p>
                        {t("Submission")} {submission}
                    </p>
                    {status ? (
                        <Facts values={status} />
                    ) : (
                        <p role="status">{t("Status wird geladen …")}</p>
                    )}
                    <p>
                        {t(
                            "„completed“ bestätigt die Inventarverarbeitung; Matching und Finding-Auswertung erfolgen getrennt.",
                        )}
                    </p>
                    <div className="actions">
                        <button onClick={() => setReload((v) => v + 1)}>
                            {t("Status erneut abrufen")}
                        </button>
                        <button onClick={() => setPoll((v) => !v)}>
                            {poll
                                ? t("Automatische Statusabfrage stoppen")
                                : t("Statusabfrage begrenzt fortsetzen")}
                        </button>
                    </div>
                    <p>
                        {t(
                            "Höchstens zwölf Abfragen im Abstand von fünf Sekunden; die Submission kann über diese interne Adresse erneut geöffnet werden.",
                        )}
                    </p>
                </Card>
            )}
        </>
    );
}

function InventoryPreview({ draft }: { draft: InventoryDraft }) {
    useLocale();
    const host = draft.value.host as Row;
    const os = draft.value.os as Row | undefined;
    const osData = os?.data as Row | undefined;
    function count(key: string) {
        const section = draft.value[key] as Row | undefined;
        return Array.isArray(section?.items) ? section.items.length : 0;
    }
    return (
        <section aria-label={t("Inventarvorschau")}>
            <h2>{t("Inventar prüfen")}</h2>
            <p role="status">
                {t("Vollständig geladen · Noch nicht gespeichert")}
            </p>
            <Facts
                values={{
                    Hostname: host.hostname,
                    "Monitoring-ID": host.monitoring_id ?? t("Nicht angegeben"),
                    "Inventar-ID": draft.value.inventory_id,
                    "Schema-Version": draft.value.schema_version,
                    Betriebssystem:
                        osData?.distribution ?? t("Nicht angegeben"),
                    [t("Installierte Pakete")]: count("packages"),
                    Container: count("containers"),
                    Images: count("images"),
                }}
            />
            <details>
                <summary>{t("Vollständiges Inventar anzeigen")}</summary>
                <pre className="inventory-preview">{draft.raw}</pre>
            </details>
        </section>
    );
}
