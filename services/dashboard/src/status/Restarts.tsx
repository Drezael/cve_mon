import { translateMessage, intlLocale, t, localized, useLocale } from "../i18n";
import {
    createContext,
    useContext,
    useRef,
    useState,
    type ReactNode,
} from "react";
import { z } from "zod";
import { api } from "../api";
import { useAuth } from "../auth";
import { useData } from "../ui";

const restart = z.object({
    id: z.string(),
    service_id: z.string(),
    state: z.string(),
    reason: z.string(),
    requested_at: z.string(),
    execution_id: z.string().nullable(),
    error_code: z.string().nullable(),
});
const target = z.object({
    id: z.string(),
    name: z.string(),
    container: z.string(),
});
const schema = z.object({ items: z.array(restart), targets: z.array(target) });
type Target = z.infer<typeof target>;
const labels: Record<string, string> = localized({
    waiting: "Wartet auf n8n",
    authorized: "Von n8n freigegeben",
    running: "Prozess startet neu",
    succeeded: "Erfolgreich neu gestartet",
    failed: "Neustart fehlgeschlagen",
    cancelled: "Abgebrochen",
});
const pending = (state: string) =>
    ["waiting", "authorized", "running"].includes(state);
// Each pipeline offers only its primary worker, never a restart of every member.
const pipelineTargets: Record<string, string> = {
    "pipeline-inventory": "inventory",
    "pipeline-cve": "importer",
    "pipeline-matching": "matcher",
    "pipeline-notifications": "notification",
};
const Context = createContext<{
    data: z.infer<typeof schema> | null;
    error: Error | null;
    refresh: () => void;
    choose: (target: Target) => void;
    message: { service: string } | null;
} | null>(null);

export default function Restarts({ children }: { children: ReactNode }) {
    useLocale();
    const { identity } = useAuth();
    return identity?.permissions.includes("deployment:service:restart") ? (
        <Provider key={identity.privateKey}>{children}</Provider>
    ) : (
        <>{children}</>
    );
}

export function StatusRefresh({ onRefresh }: { onRefresh: () => void }) {
    useLocale();
    const context = useContext(Context);
    return (
        <>
            <button
                onClick={() => {
                    onRefresh();
                    context?.refresh();
                }}
            >
                {t("Status aktualisieren")}
            </button>
            {context?.error && (
                <p role="alert">
                    {t(
                        "Neustartstatus nicht verfügbar. Bitte den Status erneut aktualisieren.",
                    )}
                </p>
            )}
        </>
    );
}

export function RestartActions({ entityId }: { entityId: string }) {
    useLocale();
    const context = useContext(Context);
    if (!context) return null;
    if (!context.data) return null;
    const id = pipelineTargets[entityId] ?? entityId;
    const target = context.data.targets.find((t) => t.id === id);
    if (!target) return null;
    const records = context.data.items.filter(
        (r) => r.service_id === target.id,
    );
    const active = records.find((r) => pending(r.state));
    const latest = active ?? records[0];
    return (
        <div className="service-restarts">
            <div className="restart-description">
                {latest && (
                    <p>
                        {labels[latest.state] ?? latest.state} ·{" "}
                        {new Date(latest.requested_at).toLocaleString(
                            intlLocale(),
                        )}
                        {latest.error_code && " · " + latest.error_code}
                    </p>
                )}
                {context.message?.service === target.id && (
                    <p role="status">
                        {t(
                            "Neustartauftrag für {0} wurde eingereiht. n8n übernimmt die Freigabe.",
                            [t(target.name)],
                        )}
                    </p>
                )}
            </div>
            <button
                disabled={!!active}
                aria-label={t(target.name) + t(" neu starten")}
                title={t(target.name) + t(" neu starten")}
                onClick={() => context.choose(target)}
            >
                {t("Neu starten")}
            </button>
        </div>
    );
}

function Provider({ children }: { children: ReactNode }) {
    useLocale();
    const result = useData("/api/v1/status/admin/restarts", schema);
    const [selected, setSelected] = useState<Target | null>(null);
    const [reason, setReason] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<Error | null>(null);
    const [message, setMessage] = useState<{
        service: string;
    } | null>(null);
    const key = useRef<string | null>(null);
    function choose(value: Target) {
        setSelected(value);
        setReason("");
        setError(null);
        setMessage(null);
        key.current = null;
    }
    async function submit() {
        if (!selected || busy) return;
        setBusy(true);
        setError(null);
        key.current ??= crypto.randomUUID();
        try {
            await api(
                "/api/v1/status/services/" + selected.id + "/restart",
                restart,
                {
                    method: "POST",
                    body: { reason },
                    idempotencyKey: key.current,
                },
            );
            setMessage({ service: selected.id });
            setSelected(null);
            key.current = null;
            setReason("");
            result.reload();
        } catch (e) {
            setError(e as Error);
        } finally {
            setBusy(false);
        }
    }
    return (
        <Context.Provider
            value={{
                data: result.data,
                error: result.error,
                refresh: result.reload,
                choose,
                message,
            }}
        >
            {children}
            {selected && (
                <div className="modal-backdrop">
                    <section
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="restart-title"
                        className="modal"
                    >
                        <h2 id="restart-title">
                            {t(selected.name)} {t("neu starten?")}
                        </h2>
                        <p>
                            {t(
                                "Der Prozess beendet seine laufende Arbeit und startet neu. Der Container wird nicht neu gestartet.",
                            )}
                        </p>
                        <form
                            onSubmit={(e) => {
                                e.preventDefault();
                                void submit();
                            }}
                        >
                            <label>
                                {t("Grund für den Neustart")}
                                <input
                                    autoFocus
                                    required
                                    minLength={3}
                                    maxLength={256}
                                    value={reason}
                                    onChange={(e) => {
                                        setReason(e.target.value);
                                        key.current = null;
                                    }}
                                    disabled={busy}
                                />
                            </label>
                            {error && (
                                <p role="alert">
                                    {translateMessage(error.message)}
                                </p>
                            )}
                            <button
                                type="submit"
                                disabled={busy || reason.trim().length < 3}
                            >
                                {busy
                                    ? t("Wird eingereiht …")
                                    : t("Über n8n neu starten")}
                            </button>
                            <button
                                type="button"
                                disabled={busy}
                                onClick={() => setSelected(null)}
                            >
                                {t("Abbrechen")}
                            </button>
                        </form>
                    </section>
                </div>
            )}
        </Context.Provider>
    );
}
