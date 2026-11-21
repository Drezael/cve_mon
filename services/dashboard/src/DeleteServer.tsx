import { translateMessage, t, useLocale } from "./i18n";
import { useState } from "react";
import { z } from "zod";
import { api } from "./api";
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
            });
            setConfirm(false);
            onDeleted();
        } catch (e) {
            setError(
                e instanceof Error
                    ? e.message
                    : t("Der Server konnte nicht gelöscht werden."),
            );
        } finally {
            setBusy(false);
        }
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
                        <button
                            disabled={busy}
                            onClick={() => setConfirm(false)}
                        >
                            {t("Abbrechen")}
                        </button>
                        <button
                            className="danger"
                            disabled={busy}
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
