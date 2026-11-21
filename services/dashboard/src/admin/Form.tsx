import { translateMessage, t, localized, useLocale } from "../i18n";
import { useId, useEffect, useRef, useState, type ReactNode } from "react";
import { useBlocker } from "react-router-dom";
import { z } from "zod";
import { api, ApiError, authResult } from "../api";
import { useAuth } from "../auth";
import { State, Pagination, useData } from "../ui";
import { row, listing, rows, type Row, text, selected } from "./contracts";
import { label } from "../format";
const selectorSchema = z.union([rows, listing]);
export type Field = {
    key: string;
    label: string;
    type?:
        | "text"
        | "textarea"
        | "password"
        | "email"
        | "number"
        | "datetime-local"
        | "time"
        | "checkbox"
        | "select"
        | "multi"
        | "picker";
    required?: boolean;
    min?: number;
    max?: number;
    step?: string;
    options?: { id: string; name: string }[];
    source?: string;
    arraySource?: boolean;
    multiple?: boolean;
    hint?: string;
};
export const options = (values: string[]) =>
    values.map((id) => ({ id, name: label(id) }));
export const reason: Field = localized({
    key: "reason",
    label: "Begründung",
    type: "textarea",
    required: true,
    min: 3,
    max: 256,
});
export function Allowed({
    permission,
    children,
}: {
    permission: string;
    children: ReactNode;
}) {
    useLocale();
    const { identity } = useAuth();
    return identity?.permissions.includes(permission) ? children : null;
}
export function Modal({
    title,
    children,
    onCancel,
}: {
    title: string;
    children: ReactNode;
    onCancel: () => void;
}) {
    useLocale();
    const titleId = useId();
    const ref = useRef<HTMLDialogElement>(null);
    const previous = useRef<Element | null>(null);
    useEffect(() => {
        previous.current = document.activeElement;
        const d = ref.current;
        if (d && !d.open) d.showModal();
        return () => {
            d?.close();
            if (previous.current instanceof HTMLElement)
                previous.current.focus();
        };
    }, []);
    return (
        <dialog
            ref={ref}
            onCancel={(e) => {
                e.preventDefault();
                onCancel();
            }}
            aria-labelledby={titleId}
        >
            <h2 id={titleId}>{translateMessage(title)}</h2>
            {children}
        </dialog>
    );
}
function Picker({
    field,
    value,
    onChange,
}: {
    field: Field;
    value: unknown;
    onChange: (v: unknown) => void;
}) {
    useLocale();
    const [search, setSearch] = useState("");
    const [offset, setOffset] = useState(0);
    const [query, setQuery] = useState("");
    const path =
        (field.source ?? "") +
        ((field.source ?? "").includes("?") ? "&" : "?") +
        new URLSearchParams({
            search: query,
            limit: "25",
            offset: String(offset),
        });
    const paged = useData(
        field.arraySource ? (field.source ?? "") : path,
        selectorSchema,
    );
    const data = paged.data;
    const { identity } = useAuth();
    const list = (Array.isArray(data) ? data : data?.items)?.filter(
        (r) =>
            !field.source?.endsWith("/roles") ||
            identity?.permissions.includes("role:assign:privileged") ||
            ["user", "viewer", "security_analyst"].includes(text(r, "code")),
    );
    const ids = field.multiple ? selected(value) : [String(value ?? "")];
    return (
        <fieldset className="picker">
            <legend>{translateMessage(field.label)}</legend>
            {!field.arraySource && (
                <div className="filters">
                    <label>
                        {t("Suche in")} {translateMessage(field.label)}
                        <input
                            value={search}
                            maxLength={128}
                            onChange={(e) => setSearch(e.target.value)}
                        />
                    </label>
                    <button
                        type="button"
                        onClick={() => {
                            setQuery(search);
                            setOffset(0);
                        }}
                    >
                        {t("Auswahl suchen")}
                    </button>
                </div>
            )}
            {list ? (
                list.map((r) => {
                    const id = text(r, "id");
                    return (
                        <label className="check" key={id}>
                            <input
                                type={field.multiple ? "checkbox" : "radio"}
                                name={field.key}
                                checked={ids.includes(id)}
                                onChange={(e) =>
                                    onChange(
                                        field.multiple
                                            ? e.target.checked
                                                ? [...ids, id]
                                                : ids.filter((v) => v !== id)
                                            : id,
                                    )
                                }
                            />
                            {text(r, "display_name") ||
                                text(r, "name") ||
                                text(r, "username") ||
                                id}
                        </label>
                    );
                })
            ) : (
                <State error={paged.error} reload={paged.reload} />
            )}
            <p className="muted">
                {ids.filter(Boolean).length}{" "}
                {t("ausgewählt. Auswahl bleibt über Seitenwechsel erhalten.")}
            </p>
            {!field.multiple && (
                <button type="button" onClick={() => onChange(null)}>
                    {t("Keine Zuordnung")}
                </button>
            )}
            {data && !Array.isArray(data) && (
                <Pagination
                    offset={offset}
                    total={data.total}
                    onChange={setOffset}
                />
            )}
        </fieldset>
    );
}
export function Inputs({
    fields,
    values,
    set,
}: {
    fields: Field[];
    values: Row;
    set: (key: string, value: unknown) => void;
}) {
    useLocale();
    return (
        <>
            {fields.map((f) =>
                f.type === "picker" ? (
                    <Picker
                        key={f.key}
                        field={f}
                        value={values[f.key]}
                        onChange={(v) => set(f.key, v)}
                    />
                ) : f.type === "multi" ? (
                    <fieldset key={f.key}>
                        <legend>{translateMessage(f.label)}</legend>
                        {f.options?.map((o) => (
                            <label className="check" key={o.id}>
                                <input
                                    type="checkbox"
                                    checked={selected(values[f.key]).includes(
                                        o.id,
                                    )}
                                    onChange={(e) =>
                                        set(
                                            f.key,
                                            e.target.checked
                                                ? [
                                                      ...selected(
                                                          values[f.key],
                                                      ),
                                                      o.id,
                                                  ]
                                                : selected(
                                                      values[f.key],
                                                  ).filter((v) => v !== o.id),
                                        )
                                    }
                                />
                                {translateMessage(o.name)}
                            </label>
                        ))}
                    </fieldset>
                ) : f.type === "checkbox" ? (
                    <label className="check" key={f.key}>
                        <input
                            type="checkbox"
                            checked={values[f.key] === true}
                            onChange={(e) => set(f.key, e.target.checked)}
                        />
                        {translateMessage(f.label)}
                    </label>
                ) : (
                    <label key={f.key}>
                        {translateMessage(f.label)}
                        {f.type === "select" ? (
                            <select
                                aria-label={translateMessage(f.label)}
                                required={f.required}
                                value={String(values[f.key] ?? "")}
                                onChange={(e) => set(f.key, e.target.value)}
                            >
                                {!f.required && (
                                    <option value="">
                                        {t("Keine Auswahl")}
                                    </option>
                                )}
                                {f.options?.map((o) => (
                                    <option key={o.id} value={o.id}>
                                        {translateMessage(o.name)}
                                    </option>
                                ))}
                            </select>
                        ) : f.type === "textarea" ? (
                            <textarea
                                aria-label={translateMessage(f.label)}
                                required={f.required}
                                minLength={f.min}
                                maxLength={f.max}
                                value={String(values[f.key] ?? "")}
                                onChange={(e) => set(f.key, e.target.value)}
                                rows={4}
                            />
                        ) : (
                            <input
                                aria-label={translateMessage(f.label)}
                                type={f.type ?? "text"}
                                autoComplete={
                                    f.type === "password" ? "off" : undefined
                                }
                                required={f.required}
                                min={f.type === "number" ? f.min : undefined}
                                max={f.type === "number" ? f.max : undefined}
                                minLength={
                                    f.type === "number" ? undefined : f.min
                                }
                                maxLength={
                                    f.type === "number" ? undefined : f.max
                                }
                                step={f.step}
                                value={String(values[f.key] ?? "")}
                                onChange={(e) =>
                                    set(
                                        f.key,
                                        f.type === "number"
                                            ? e.target.value === ""
                                                ? null
                                                : Number(e.target.value)
                                            : e.target.value,
                                    )
                                }
                            />
                        )}{" "}
                        {f.hint && <small>{translateMessage(f.hint)}</small>}
                    </label>
                ),
            )}
        </>
    );
}
export type Mutation = {
    title: string;
    path: string;
    method: "POST" | "PATCH" | "PUT" | "DELETE";
    fields: Field[];
    initial?: Row;
    version?: number;
    stepUp?: boolean;
    critical?: boolean;
    idempotent?: boolean;
    dirty?: boolean;
    payload?: (values: Row) => unknown;
    validate?: (values: Row) => string | null;
};
export function EditForm({
    operation,
    onDone,
    onCancel,
    onReload,
}: {
    operation: Mutation;
    onDone: (result: Row | null) => void;
    onCancel: () => void;
    onReload: () => void;
}) {
    useLocale();
    const [values, setValues] = useState<Row>(operation.initial ?? {});
    const [busy, setBusy] = useState(false);
    const lock = useRef(false);
    const dirty = useRef(operation.dirty ?? false);
    const container = useRef<HTMLElement>(null);
    const pendingButton = useRef<HTMLButtonElement | null>(null);
    const alive = useRef(true);
    const controller = useRef(new AbortController());
    useEffect(() => {
        alive.current = true;
        controller.current = new AbortController();
        return () => {
            alive.current = false;
            controller.current.abort();
        };
    }, []);
    const [error, setError] = useState<ApiError | Error | null>(null);
    const [stage, setStage] = useState<"confirm" | "reauth" | null>(null);
    const [password, setPassword] = useState("");
    const [code, setCode] = useState("");
    const [uncertain, setUncertain] = useState(false);
    const blocker = useBlocker(() => dirty.current);
    const set = (k: string, v: unknown) => {
        dirty.current = true;
        setValues((old) => ({ ...old, [k]: v }));
    };
    useEffect(() => {
        const warn = (e: BeforeUnloadEvent) => {
            if (dirty.current) {
                e.preventDefault();
                e.returnValue = "";
            }
        };
        window.addEventListener("beforeunload", warn);
        return () => window.removeEventListener("beforeunload", warn);
    }, []);

    const [discard, setDiscard] = useState(false);
    useEffect(() => {
        const guard = (event: MouseEvent) => {
            const button =
                event.target instanceof Element
                    ? event.target.closest("button")
                    : null;
            if (
                button instanceof HTMLButtonElement &&
                dirty.current &&
                !container.current?.contains(button) &&
                button.textContent?.trim() !== t("Abmelden")
            ) {
                event.preventDefault();
                event.stopPropagation();
                if (!lock.current) {
                    pendingButton.current = button;
                    setDiscard(true);
                }
            }
        };
        document.addEventListener("click", guard, true);
        return () => document.removeEventListener("click", guard, true);
    }, []);
    const stop = () => {
        if (dirty.current) setDiscard(true);
        else onCancel();
    };
    async function send() {
        if (lock.current) return;
        lock.current = true;
        setBusy(true);
        setError(null);
        try {
            if (operation.stepUp !== false) {
                await api("/api/v1/auth/reauthenticate", authResult, {
                    method: "POST",
                    signal: controller.current.signal,
                    body: { password, ...(code ? { code } : {}) },
                });
                setPassword("");
                setCode("");
            }
            const result = await api(operation.path, z.union([row, z.null()]), {
                method: operation.method,
                signal: controller.current.signal,
                body: operation.payload ? operation.payload(values) : values,
                version: operation.version,
            });
            if (!alive.current) return;
            dirty.current = false;
            setStage(null);
            onDone(result);
            if (/\/admin\/(users|roles|server-access)/.test(operation.path)) {
                window.dispatchEvent(new Event("authorization-changed"));
                const channel = new BroadcastChannel("cve-session");
                channel.postMessage("permissions-changed");
                channel.close();
            }
        } catch (e) {
            if (!alive.current) return;
            setPassword("");
            setCode("");
            const problem = e instanceof Error ? e : new ApiError(0);
            setError(problem);
            if (
                problem instanceof ApiError &&
                [0, 504, 502, 503].includes(problem.status)
            )
                setUncertain(true);
            setStage(null);
        } finally {
            lock.current = false;
            setBusy(false);
        }
    }
    function begin() {
        setError(null);
        const invalid = operation.validate?.(values);
        if (invalid) {
            setError(new Error(invalid));
            return;
        }
        if (operation.critical) setStage("confirm");
        else if (operation.stepUp !== false) setStage("reauth");
        else void send();
    }
    return (
        <section ref={container} className="card admin-form">
            <h2>{translateMessage(operation.title)}</h2>
            <form
                onSubmit={(e) => {
                    e.preventDefault();
                    begin();
                }}
            >
                <fieldset disabled={busy || uncertain}>
                    <Inputs
                        fields={operation.fields}
                        values={values}
                        set={set}
                    />
                </fieldset>
                {error && (
                    <div className="notice" role="alert">
                        <p>{translateMessage(error.message)}</p>
                        {error instanceof ApiError &&
                            error.fields.length > 0 && (
                                <p>
                                    {t("Eingaben prüfen:")}{" "}
                                    {error.fields.join(", ")}
                                </p>
                            )}
                        {error instanceof ApiError &&
                            [409, 412, 428].includes(error.status) && (
                                <p>
                                    {t(
                                        "Versionskonflikt. Ihre Eingaben wurden nicht überschrieben. Laden Sie den aktuellen Stand und prüfen Sie die Änderung erneut.",
                                    )}
                                </p>
                            )}
                        {uncertain && (
                            <p>
                                {t(
                                    "Das Ergebnis ist unbekannt. Es erfolgt keine automatische Wiederholung. Prüfen Sie den bestätigten Serverstand.",
                                )}
                            </p>
                        )}
                        <button
                            type="button"
                            onClick={() => {
                                dirty.current = false;
                                onReload();
                            }}
                        >
                            {t("Aktuellen Stand neu laden")}
                        </button>
                        {uncertain && operation.idempotent && (
                            <button
                                type="button"
                                onClick={() => {
                                    setUncertain(false);
                                }}
                            >
                                {t(
                                    "Dieselbe idempotente Anfrage prüfen und erneut verwenden",
                                )}
                            </button>
                        )}
                    </div>
                )}
                <div className="actions">
                    <button type="button" onClick={stop} disabled={busy}>
                        {t("Abbrechen")}
                    </button>
                    <button type="submit" disabled={busy || uncertain}>
                        {busy ? t("Wird gespeichert …") : t("Speichern")}
                    </button>
                </div>
            </form>
            {stage === "confirm" && (
                <Modal
                    title={t("Kritische Änderung bestätigen")}
                    onCancel={() => setStage(null)}
                >
                    <p>{translateMessage(operation.title)}</p>
                    <p>
                        {t(
                            "Diese Aktion wird mit Ihren aktuellen Rechten und dem geladenen Versionsstand geprüft.",
                        )}
                    </p>
                    <div className="actions">
                        <button autoFocus onClick={() => setStage(null)}>
                            {t("Abbrechen")}
                        </button>
                        <button
                            onClick={() => {
                                if (operation.stepUp === false) void send();
                                else setStage("reauth");
                            }}
                        >
                            {t("Änderung bestätigen")}
                        </button>
                    </div>
                </Modal>
            )}
            {stage === "reauth" && (
                <Modal
                    title={t("Identität erneut bestätigen")}
                    onCancel={() => {
                        setStage(null);
                        setPassword("");
                        setCode("");
                    }}
                >
                    <form
                        onSubmit={(e) => {
                            e.preventDefault();
                            void send();
                        }}
                    >
                        <p>{translateMessage(operation.title)}</p>
                        <label>
                            {t("Aktuelles Passwort")}
                            <input
                                type="password"
                                autoComplete="current-password"
                                required
                                maxLength={256}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
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
                                onChange={(e) => setCode(e.target.value)}
                            />
                        </label>
                        <div className="actions">
                            <button
                                autoFocus
                                type="button"
                                onClick={() => {
                                    setStage(null);
                                    setPassword("");
                                    setCode("");
                                }}
                            >
                                {t("Abbrechen")}
                            </button>
                            <button disabled={busy} type="submit">
                                {t("Identität bestätigen und speichern")}
                            </button>
                        </div>
                    </form>
                </Modal>
            )}
            {(discard || blocker.state === "blocked") && (
                <Modal
                    title={t("Ungespeicherte Änderungen")}
                    onCancel={() => {
                        setDiscard(false);
                        if (blocker.state === "blocked") blocker.reset();
                    }}
                >
                    <p>
                        {t("Die Eingaben für")}{" "}
                        {translateMessage(operation.title)}{" "}
                        {t("wurden noch nicht gespeichert.")}
                    </p>
                    <div className="actions">
                        <button
                            autoFocus
                            onClick={() => {
                                setDiscard(false);
                                if (blocker.state === "blocked")
                                    blocker.reset();
                            }}
                        >
                            {t("Weiter bearbeiten")}
                        </button>
                        <button
                            onClick={() => {
                                dirty.current = false;
                                if (blocker.state === "blocked")
                                    blocker.proceed();
                                else {
                                    onCancel();
                                    const button = pendingButton.current;
                                    pendingButton.current = null;
                                    if (button)
                                        setTimeout(() => button.click(), 0);
                                }
                            }}
                        >
                            {t("Änderungen verwerfen")}
                        </button>
                    </div>
                </Modal>
            )}
        </section>
    );
}

export function DraftGuard({
    dirty,
    onDiscard,
}: {
    dirty: boolean;
    onDiscard: () => void;
}) {
    useLocale();
    const blocker = useBlocker(dirty);
    useEffect(() => {
        const warn = (e: BeforeUnloadEvent) => {
            if (dirty) {
                e.preventDefault();
                e.returnValue = "";
            }
        };
        window.addEventListener("beforeunload", warn);
        return () => window.removeEventListener("beforeunload", warn);
    }, [dirty]);
    return blocker.state === "blocked" ? (
        <Modal
            title={t("Ungespeicherte Änderungen")}
            onCancel={() => blocker.reset()}
        >
            <p>
                {t(
                    "Die noch nicht bestätigten Änderungen gehen beim Verlassen verloren.",
                )}
            </p>
            <div className="actions">
                <button autoFocus onClick={() => blocker.reset()}>
                    {t("Weiter bearbeiten")}
                </button>
                <button
                    onClick={() => {
                        onDiscard();
                        blocker.proceed();
                    }}
                >
                    {t("Änderungen verwerfen")}
                </button>
            </div>
        </Modal>
    ) : null;
}
