import { useRef, useState } from "react";
import { z } from "zod";
import { api } from "./api";
import { t, translateMessage, useLocale } from "./i18n";
const receipt = z.object({
    job_id: z.string(),
    snapshot_id: z.string(),
    state: z.string(),
});
export default function ScanServer({
    id,
    enabled,
}: {
    id: string;
    enabled: boolean;
}) {
    useLocale();
    const [busy, setBusy] = useState(false);
    const [message, setMessage] = useState("");
    const key = useRef(crypto.randomUUID());
    async function scan() {
        if (busy) return;
        setBusy(true);
        setMessage("");
        try {
            await api(`/api/v1/dashboard/servers/${id}/scan`, receipt, {
                method: "POST",
                idempotencyKey: key.current,
            });
            setMessage(t("Vollscan wurde über n8n eingereiht."));
            key.current = crypto.randomUUID();
        } catch (e) {
            setMessage(
                e instanceof Error
                    ? translateMessage(e.message)
                    : t("Scan konnte nicht gestartet werden."),
            );
        } finally {
            setBusy(false);
        }
    }
    return (
        <span>
            <button disabled={!enabled || busy} onClick={() => void scan()}>
                {busy ? t("Wird eingereiht …") : t("Scan")}
            </button>
            {message && <small role="status">{message}</small>}
        </span>
    );
}
