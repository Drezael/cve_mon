import { t, useLocale } from "./i18n";
import { useEffect, useState } from "react";
import { z } from "zod";
import { api } from "./api";
import { number } from "./format";
import { useAuth } from "./auth";
import {
    FINDINGS_CHANGED,
    FINDINGS_REFRESH,
    FINDINGS_REFRESH_INTERVAL,
} from "./finding-refresh";

const schema = z.object({ count: z.number().int().nonnegative() });
export default function FindingCountBadge() {
    useLocale();
    const { identity } = useAuth();
    return identity?.permissions.includes("finding:read") ? (
        <Count key={identity.privateKey} />
    ) : null;
}
function Count() {
    useLocale();
    const [count, setCount] = useState<number | null>(null);
    useEffect(() => {
        const controller = new AbortController();
        let timer: ReturnType<typeof setTimeout>;
        let loading = false;
        let pending = false;
        let previous: number | null = null;
        async function load() {
            if (loading) {
                pending = true;
                return;
            }
            clearTimeout(timer);
            loading = true;
            try {
                const result = await api(
                    "/api/v1/findings/active-count",
                    schema,
                    { signal: controller.signal },
                );
                if (!controller.signal.aborted) {
                    setCount(result.count);
                    if (previous !== null && previous !== result.count)
                        window.dispatchEvent(new Event(FINDINGS_CHANGED));
                    previous = result.count;
                }
            } catch {
                if (!controller.signal.aborted) setCount(null);
            }
            loading = false;
            if (!controller.signal.aborted) {
                timer = setTimeout(
                    () => void load(),
                    pending ? 0 : FINDINGS_REFRESH_INTERVAL,
                );
                pending = false;
            }
        }
        const refresh = () => {
            void load();
        };
        window.addEventListener(FINDINGS_REFRESH, refresh);
        void load();
        return () => {
            window.removeEventListener(FINDINGS_REFRESH, refresh);
            controller.abort();
            clearTimeout(timer);
        };
    }, []);
    return count && count > 0 ? (
        <span
            className="nav-finding-count"
            aria-label={
                count === 1
                    ? t("1 aktuelles Finding")
                    : t("{0} aktuelle Findings", [number(count)])
            }
        >
            {number(count)}
        </span>
    ) : null;
}
