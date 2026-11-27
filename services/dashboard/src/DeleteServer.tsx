import { translateMessage, t, useLocale } from "./i18n";
import { useState, useRef } from "react";
import { z } from "zod";
import { api, ApiError } from "./api";
import { Modal } from "./admin/Form";

export default function DeleteServer({
    server,
    onDeleted,
}: {
    server: {
        id: string;
        display_name: string;
        version: number;
        can_delete: boolean;
    };
    onDeleted: () => void;
}) {
    useLocale();
    const [confirm, setConfirm] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const operationId = useRef(crypto.randomUUID());
    const [uncertain, setUncertain] = useState(false);
    if (!server.can_delete) return null;
    async function remove() {
        if (busy) return;
        setBusy(true);
        setError("");
        try {
            await api(`/api/v1/dashboard/servers/${server.id}`, z.unknown(), {
                method: "DELETE",
                timeoutMs: 60000,
                version: server.version,
                idempotencyKey: operationId.current,
            });
            setConfirm(false);
            onDeleted();
        } catch (e) {
            if (e instanceof ApiError && [0, 503, 504].includes(e.status)) setUncertain(true);
            setError(
                e instanceof Error
                    ? e.message
                    : t("Der Server konnte nicht gelöscht werden."),
            );
        } finally {
            setBusy(false);
        }
    }
    async function checkStatus() {
        setBusy(true);
        try {
            const result = await api(`/api/v1/dashboard/servers/erase-operations/${operationId.current}`, z.object({ state: z.string() }));
            if (result.state === "completed") { setConfirm(false); onDeleted(); }
            else setError(result.state === "failed" ? t("Löschung fehlgeschlagen.") : t("Löschung läuft noch."));
        } catch { setError(t("Status derzeit nicht verfügbar. Bitte erneut prüfen.")); }
        finally { setBusy(false); }
    }
    return (
        <>
            <button
                className="danger"
                aria-label={t("Server {0} löschen", [server.display_name])}
                onClick={() => setConfirm(true)}
            >
                {t("Löschen")}
            </button>
            {confirm && (
                <Modal
                    title={t("Server löschen")}
                    onCancel={() => {
                        if (!busy) setConfirm(false);
                    }}
                >
                    <p>
                        {t(
                            "„{0}“ endgültig löschen? Weitere Prüfungen und Uploads für diesen Server werden gestoppt. Inventare, Findings, Historien, Zugangsdaten und Aktualisierungsjobs werden vollständig entfernt. Diese Aktion kann nicht rückgängig gemacht werden. Ältere verwaltete Sicherungen, die Serverdaten enthalten, werden ebenfalls verworfen.",
                            [server.display_name],
                        )}
                    </p>
                    {error && (
                        <p role="alert">
                            {translateMessage(error)}
                            {t(
                                " Keine automatische Wiederholung. Der Abbruchgrund wird im Löschprotokoll festgehalten.",
                            )}
                        </p>
                    )}
                    <div className="actions">
                        {uncertain && <button disabled={busy} onClick={() => void checkStatus()}>{t("Status prüfen")}</button>}
                        <button
                            disabled={busy}
                            onClick={() => setConfirm(false)}
                        >
                            {t("Abbrechen")}
                        </button>
                        <button
                            className="danger"
                            disabled={busy || uncertain}
                            onClick={() => void remove()}
                        >
                            {busy ? t("Wird gelöscht …") : t("Server löschen")}
                        </button>
                    </div>
                </Modal>
            )}
        </>
    );
}
