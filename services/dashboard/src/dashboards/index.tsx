import { z } from "zod";
import { useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { Link, useNavigate, useParams } from "react-router-dom";
import { t, translateMessage, useLocale } from "../i18n";
import { api, ApiError } from "../api";
import { Card, State, useData } from "../ui";
import { DraftGuard, EditForm, Modal, type Mutation } from "../admin/Form";
import Board from "./Board";
import {
    dashboardListSchema,
    dashboardSchema,
    endpoint,
    validationSchema,
    type DashboardConfig,
} from "./contracts";

function example() {
    return `version: 1
title: ${JSON.stringify(t("Neues Dashboard"))}
description: ""
layout:
  columns: 2
refresh_interval_seconds: 0
widgets: []
`;
}
function download(source: string, id = "example") {
    const url = URL.createObjectURL(
        new Blob([source], { type: "application/yaml;charset=utf-8" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `dashboard-${id}.yaml`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export default function Dashboards() {
    useLocale();
    const result = useData(endpoint, dashboardListSchema);
    const { id } = useParams();
    const navigate = useNavigate();
    const selected = id ?? result.data?.items[0]?.id;
    return (
        <>
            <header className="page-header">
                <h1>{t("Dashboards")}</h1>
                <div className="actions">
                    <button onClick={() => navigate("/dashboards/new")}>
                        {t("Erstellen")}
                    </button>
                    <button
                        disabled={!selected}
                        onClick={() => navigate(`/dashboards/${selected}/edit`)}
                    >
                        {t("Bearbeiten")}
                    </button>
                </div>
            </header>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <label className="dashboard-selector">
                        {t("Dashboard auswählen")}
                        <select
                            value={selected ?? ""}
                            disabled={!result.data.items.length}
                            onChange={(e) =>
                                navigate(`/dashboards/${e.target.value}`)
                            }
                        >
                            {!result.data.items.length && (
                                <option value="">
                                    {t("Keine Dashboards vorhanden")}
                                </option>
                            )}
                            {result.data.items.map((d) => (
                                <option key={d.id} value={d.id}>
                                    {d.title}
                                    {!d.can_edit
                                        ? ` (${t("Geteilt von {0}", [d.owner_username])})`
                                        : ""}
                                </option>
                            ))}
                        </select>
                    </label>
                    {selected ? (
                        <SelectedDashboard
                            id={selected}
                            key={selected}
                            onDeleted={() => {
                                result.reload();
                                navigate("/dashboards");
                            }}
                        />
                    ) : (
                        <p>{t("Noch keine eigenen Dashboards")}</p>
                    )}
                </>
            )}
        </>
    );
}
export function DashboardDetail() {
    return <Dashboards />;
}
function SelectedDashboard({
    id,
    onDeleted,
}: {
    id: string;
    onDeleted: () => void;
}) {
    useLocale();
    const result = useData(endpoint + "/" + id, dashboardSchema);
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [share, setShare] = useState(false);
    const [revision, setRevision] = useState(0);
    const d = result.data;
    if (!d) return <State error={result.error} reload={result.reload} />;
    return (
        <>
            <section className="dashboard-toolbar">
                <div>
                    <h2>{d.title}</h2>
                    <p>{d.config.description}</p>
                    {!d.can_edit && (
                        <p>{t("Geteilt von {0}", [d.owner_username])}</p>
                    )}
                </div>
                <div className="actions">
                    <button onClick={() => download(d.yaml, id)}>
                        {t("YAML exportieren")}
                    </button>
                    <button
                        onClick={() => {
                            result.reload();
                            setRevision((v) => v + 1);
                        }}
                    >
                        {t("Aktualisieren")}
                    </button>
                    {d.can_edit && (
                        <>
                            <button onClick={() => setShare(true)}>
                                {t("Teilen")}
                            </button>
                            <button
                                onClick={() =>
                                    setOperation({
                                        title: t("Dashboard löschen"),
                                        path: endpoint + "/" + id,
                                        method: "DELETE",
                                        stepUp: false,
                                        critical: true,
                                        fields: [],
                                        payload: () => ({ version: d.version }),
                                    })
                                }
                            >
                                {t("Dashboard löschen")}
                            </button>
                        </>
                    )}
                </div>
            </section>
            {share && (
                <ShareDashboard
                    id={id}
                    onClose={() => {
                        setShare(false);
                        result.reload();
                    }}
                />
            )}
            {operation && (
                <EditForm
                    operation={operation}
                    onCancel={() => setOperation(null)}
                    onDone={onDeleted}
                    onReload={() => {
                        setOperation(null);
                        result.reload();
                    }}
                />
            )}
            <Board config={d.config} key={revision} />
        </>
    );
}
const sharesSchema = z.object({
    version: z.number(),
    usernames: z.array(z.string()),
});
function ShareDashboard({ id, onClose }: { id: string; onClose: () => void }) {
    useLocale();
    const result = useData(endpoint + "/" + id + "/shares", sharesSchema);
    return result.data ? (
        <EditForm
            operation={{
                title: t("Dashboard teilen"),
                path: endpoint + "/" + id + "/shares",
                method: "PUT",
                stepUp: false,
                fields: [
                    {
                        key: "usernames",
                        label: t("Benutzernamen (kommagetrennt)"),
                        type: "textarea",
                        max: 6500,
                    },
                ],
                initial: { usernames: result.data.usernames.join(", ") },
                payload: (v) => ({
                    version: result.data!.version,
                    usernames: String(v.usernames ?? "")
                        .split(",")
                        .map((n) => n.trim())
                        .filter(Boolean),
                }),
            }}
            onCancel={onClose}
            onDone={onClose}
            onReload={result.reload}
        />
    ) : (
        <State error={result.error} reload={result.reload} />
    );
}
export function DashboardEditorPage() {
    useLocale();
    const { id } = useParams();
    return id ? (
        <ExistingEditor id={id} key={id} />
    ) : (
        <Editor key="new" initial={example()} />
    );
}
function ExistingEditor({ id }: { id: string }) {
    const result = useData(endpoint + "/" + id, dashboardSchema);
    return result.data ? (
        <Editor
            id={id}
            initial={result.data.yaml}
            version={result.data.version}
            copy={!result.data.can_edit}
            originalTitle={result.data.title}
        />
    ) : (
        <State error={result.error} reload={result.reload} />
    );
}
function Editor({
    id,
    initial,
    version,
    copy = false,
    originalTitle = "",
}: {
    id?: string;
    initial: string;
    version?: number;
    copy?: boolean;
    originalTitle?: string;
}) {
    useLocale();
    const navigate = useNavigate();
    const [source, setSource] = useState(initial);
    const [saveDialog, setSaveDialog] = useState(false);
    const [copyName, setCopyName] = useState(
        originalTitle.slice(0, 110) + " (" + t("Kopie") + ")",
    );
    const [dirty, setDirty] = useState(false);
    const [busy, setBusy] = useState(false);
    const [uncertain, setUncertain] = useState(false);
    const [preview, setPreview] = useState<DashboardConfig | null>(null);
    const [issues, setIssues] = useState<string[]>([]);
    const [error, setError] = useState<Error | null>(null);
    const locked = useRef(false);
    const controller = useRef(new AbortController());
    const fileRevision = useRef(0);
    useEffect(() => {
        controller.current = new AbortController();
        return () => controller.current.abort();
    }, []);
    const change = (value: string) => {
        setSource(value);
        setDirty(value !== initial);
        setPreview(null);
        setIssues([]);
        setError(null);
    };
    async function run(save: boolean, copyTitle?: string) {
        if (copy && save && !copyTitle) {
            setSaveDialog(true);
            return;
        }
        if (copyTitle) setSaveDialog(false);
        if (locked.current || uncertain) return;
        if (new TextEncoder().encode(source).length > 32768) {
            setIssues([t("Die YAML-Datei darf höchstens 32 KiB groß sein.")]);
            return;
        }
        locked.current = true;
        setBusy(true);
        setError(null);
        setIssues([]);
        let committing = false;
        try {
            const validation = await api(
                endpoint + "/validate",
                validationSchema,
                {
                    method: "POST",
                    body: { yaml: source },
                    signal: controller.current.signal,
                },
            );
            if (!validation.valid || !validation.config) {
                setIssues(validation.errors);
                setPreview(null);
                return;
            }
            setPreview(validation.config);
            if (!save) return;
            committing = true;
            const saved = await api(
                endpoint + (id ? "/" + id + (copy ? "/copy" : "") : ""),
                dashboardSchema,
                {
                    method: id && !copy ? "PUT" : "POST",
                    body: {
                        yaml: source,
                        ...(copy
                            ? { title: copyTitle }
                            : id
                              ? { version }
                              : {}),
                    },
                    signal: controller.current.signal,
                },
            );
            if (controller.current.signal.aborted) return;
            flushSync(() => setDirty(false));
            navigate(`/dashboards/${saved.id}`);
        } catch (problem) {
            if (controller.current.signal.aborted) return;
            setError(
                problem instanceof Error
                    ? problem
                    : new Error(t("Speichern fehlgeschlagen.")),
            );
            if (
                committing &&
                problem instanceof ApiError &&
                [0, 502, 503, 504].includes(problem.status)
            )
                setUncertain(true);
        } finally {
            locked.current = false;
            if (!controller.current.signal.aborted) setBusy(false);
        }
    }
    async function importFile(file: File | undefined) {
        if (!file) return;
        if (file.size > 32768) {
            setError(
                new Error(t("Die YAML-Datei darf höchstens 32 KiB groß sein.")),
            );
            return;
        }
        const revision = ++fileRevision.current;
        try {
            const contents = await file.text();
            if (
                fileRevision.current === revision &&
                !controller.current.signal.aborted
            )
                change(contents);
        } catch {
            setError(
                new Error(t("Die YAML-Datei konnte nicht gelesen werden.")),
            );
        }
    }
    return (
        <>
            {saveDialog && (
                <Modal
                    title={t("Als eigenes Dashboard speichern")}
                    onCancel={() => setSaveDialog(false)}
                >
                    <form
                        onSubmit={(e) => {
                            e.preventDefault();
                            void run(true, copyName);
                        }}
                    >
                        <label>
                            {t("Name")}
                            <input
                                required
                                maxLength={128}
                                value={copyName}
                                onChange={(e) => setCopyName(e.target.value)}
                            />
                        </label>
                        <div className="actions">
                            <button
                                type="button"
                                onClick={() => setSaveDialog(false)}
                            >
                                {t("Abbrechen")}
                            </button>
                            <button type="submit">{t("Speichern")}</button>
                        </div>
                    </form>
                </Modal>
            )}
            <DraftGuard dirty={dirty} onDiscard={() => setDirty(false)} />
            <header className="page-header">
                <h1>{id ? t("YAML bearbeiten") : t("Dashboard erstellen")}</h1>
                <button
                    type="button"
                    onClick={() =>
                        navigate(id ? `/dashboards/${id}` : "/dashboards")
                    }
                >
                    {t("Abbrechen")}
                </button>
            </header>
            <Card title={t("YAML-Konfiguration")}>
                <p>
                    {t(
                        "Import und Vorschau speichern noch keine Änderungen. Gespeichert wird erst mit „Speichern“.",
                    )}
                </p>
                <fieldset
                    disabled={busy || uncertain}
                    className="dashboard-editor-fields"
                >
                    <label>
                        {t("YAML-Datei importieren")}
                        <input
                            type="file"
                            accept=".yaml,.yml,application/yaml,text/yaml,text/plain"
                            onChange={(e) =>
                                void importFile(e.target.files?.[0])
                            }
                        />
                    </label>
                    <label htmlFor="dashboard-yaml">
                        {t("Dashboard-YAML")}
                    </label>
                    <textarea
                        id="dashboard-yaml"
                        className="yaml-editor"
                        value={source}
                        onChange={(e) => change(e.target.value)}
                        maxLength={32768}
                        rows={24}
                        spellCheck={false}
                        autoCapitalize="off"
                        autoCorrect="off"
                    />
                    <div className="actions">
                        <button onClick={() => void run(false)}>
                            {t("Prüfen und Vorschau")}
                        </button>
                        <button onClick={() => void run(true)}>
                            {busy ? t("Wird gespeichert …") : t("Speichern")}
                        </button>
                        <button onClick={() => download(source, id)}>
                            {t("YAML exportieren")}
                        </button>
                    </div>
                </fieldset>
                {issues.length > 0 && (
                    <div className="notice" role="alert">
                        <p>{t("Die YAML-Konfiguration ist ungültig.")}</p>
                        <ul>
                            {issues.map((issue, i) => (
                                <li key={i}>{issue}</li>
                            ))}
                        </ul>
                    </div>
                )}
                {error && (
                    <div className="notice" role="alert">
                        <p>{translateMessage(error.message)}</p>
                        {error instanceof ApiError && error.status === 409 && (
                            <p>
                                {t(
                                    "Versionskonflikt oder gleicher Dashboardname. Ihre Eingaben bleiben erhalten; prüfen Sie den gespeicherten Stand.",
                                )}
                            </p>
                        )}
                    </div>
                )}
                {uncertain && (
                    <p role="alert">
                        {t(
                            "Das Ergebnis ist unbekannt. Prüfen Sie Ihre gespeicherten Dashboards, bevor Sie erneut speichern.",
                        )}{" "}
                        <Link to="/dashboards">{t("Dashboards")}</Link>
                    </p>
                )}
                <p>
                    {t(
                        "Weitere Elemente: summary, inventory_quality, trend (days: 7, 30 oder 90), database und workflow. Datenbank- und Steuerungselemente sind nur für admin nutzbar.",
                    )}
                </p>
                <details>
                    <summary>{t("YAML-Referenz")}</summary>
                    <p>
                        {t(
                            "Version 1: title, description, layout.columns (1–3), refresh_interval_seconds (0 oder 60–3600) und widgets (0–24). Jeder Widget-Eintrag benötigt id, type und title; span ist optional.",
                        )}
                    </p>
                    <ul>
                        <li>
                            {t(
                                "metric: metric = active_servers, servers_affected, open_findings, critical, high, overdue, kev oder unknown.",
                            )}
                        </li>
                        <li>
                            {t(
                                "distribution: source = priorities, lifecycle, technical, inventory, matching oder kev_priorities.",
                            )}
                        </li>
                        <li>
                            {t(
                                "servers: limit (1–50), sort (manual, name, inventory), filters mit group_id, search oder distribution.",
                            )}
                        </li>
                        <li>
                            {t(
                                "findings: limit (1–50), filters mit server_id, group_id, priority, lifecycle, kev oder overdue.",
                            )}
                        </li>
                        <li>
                            {t(
                                "text: text enthält einfachen Text. Inhalte und Widgettitel werden unverändert angezeigt.",
                            )}
                        </li>
                    </ul>
                </details>
            </Card>
            {preview && (
                <section aria-label={t("Dashboard-Vorschau")}>
                    <h2>
                        {t("Vorschau")}: {preview.title}
                    </h2>
                    <Board config={preview} />
                </section>
            )}
        </>
    );
}
