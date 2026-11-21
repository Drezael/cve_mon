import { t, useLocale } from "./i18n";
import {
    createContext,
    useContext,
    useState,
    useEffect,
    useCallback,
    useRef,
    type ReactNode,
} from "react";
import { flushSync } from "react-dom";
import { api, clearPrivate, authResult } from "./api";
import { sessionSchema, permissionSchema } from "./contracts";
import { z } from "zod";
import { getLocaleRevision } from "./i18n/core";
import { setLocale } from "./i18n";
import {
    readLocale,
    synchronizeLocale,
    LOCALE_UPDATED,
} from "./settings/localization";
type Identity = {
    state: string;
    display_name?: string;
    permissions: string[];
    roles: string[];
    privateKey: string;
};
const Context = createContext<{
    identity: Identity | null;
    checking: boolean;
    enrollmentSecret: string | null;
    setEnrollmentSecret: (secret: string | null) => void;
    recoveryCodes: string[];
    setRecoveryCodes: (codes: string[]) => void;
    refresh: (force?: boolean) => Promise<void>;
    logoutError: string;
    logout: () => Promise<void>;
}>({
    identity: null,
    checking: true,
    logoutError: "",
    enrollmentSecret: null,
    setEnrollmentSecret: () => {},
    recoveryCodes: [],
    setRecoveryCodes: () => {},
    refresh: async () => {},
    logout: async () => {},
});
export function AuthProvider({ children }: { children: ReactNode }) {
    useLocale();
    const [enrollmentSecret, setEnrollmentSecret] = useState<string | null>(
        null,
    );
    const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
    const [identity, setIdentity] = useState<Identity | null>(null);
    const [checking, setChecking] = useState(true);
    const previousKey = useRef("");
    const refreshRevision = useRef(0);
    const stopped = useRef(false);
    const [logoutError, setLogoutError] = useState("");
    const refresh = useCallback(async (force = false) => {
        if (force) {
            stopped.current = false;
            setLogoutError("");
        }
        if (stopped.current) return;
        const revision = ++refreshRevision.current;
        const languageRevision = getLocaleRevision();
        try {
            const s = await api("/api/v1/auth/session", sessionSchema);
            const p =
                s.state === "authenticated"
                    ? await api(
                          "/api/v1/dashboard/me/permissions",
                          permissionSchema,
                      )
                    : null;
            let language;
            try {
                language = await readLocale(s.state === "authenticated");
            } catch {
                /* A language lookup must not make authentication unavailable. */
            }
            if (revision !== refreshRevision.current) return;
            if (getLocaleRevision() === languageRevision && language)
                setLocale(language);
            const privateKey = `${p?.user_id ?? ""}:${p?.authorization_version ?? ""}`;
            if (previousKey.current !== privateKey) {
                clearPrivate();
                previousKey.current = privateKey;
            }
            setIdentity({
                ...s,
                permissions: p?.permissions ?? [],
                roles: p?.roles ?? [],
                privateKey,
            });
        } catch {
            if (revision === refreshRevision.current) setIdentity(null);
        } finally {
            if (revision === refreshRevision.current) setChecking(false);
        }
    }, []);
    const logout = useCallback(async () => {
        stopped.current = true;
        refreshRevision.current += 1;
        try {
            await api("/api/v1/auth/logout", z.null(), {
                method: "POST",
                body: {},
            });
            setLogoutError("");
        } catch {
            setLogoutError(
                t(
                    "Die lokale Ansicht wurde geschlossen. Die Abmeldung am Server konnte nicht bestätigt werden; bitte bei wiederhergestellter Verbindung erneut abmelden.",
                ),
            );
        } finally {
            clearPrivate();
            setEnrollmentSecret(null);
            setRecoveryCodes([]);
            setIdentity(null);
            await synchronizeLocale(false);
            const channel = new BroadcastChannel("cve-session");
            channel.postMessage("logout");
            channel.close();
        }
    }, []);
    useEffect(() => {
        void refresh();
        const channel = new BroadcastChannel("cve-session");
        const localeChannel = new BroadcastChannel("cve-locale");
        localeChannel.onmessage = () => {
            window.dispatchEvent(new Event(LOCALE_UPDATED));
        };
        const reset = () => {
            refreshRevision.current += 1;
            clearPrivate();
            setEnrollmentSecret(null);
            setRecoveryCodes([]);
            setIdentity(null);
            setChecking(false);
            void synchronizeLocale(false);
        };
        channel.onmessage = (event) => {
            if (event.data === "permissions-changed") void refresh();
            else reset();
        };
        const changed = () => {
            void refresh();
        };
        window.addEventListener("authorization-changed", changed);
        window.addEventListener(LOCALE_UPDATED, changed);
        window.addEventListener("session-expired", reset);
        const hide = () => {
            refreshRevision.current += 1;
            clearPrivate();
            flushSync(() => {
                setEnrollmentSecret(null);
                setRecoveryCodes([]);
                setIdentity(null);
                setChecking(true);
            });
        };
        const show = () => {
            void refresh();
        };
        window.addEventListener("pagehide", hide);
        window.addEventListener("pageshow", show);
        const visible = () => {
            if (document.visibilityState === "visible") void refresh();
        };
        document.addEventListener("visibilitychange", visible);
        const timer = setInterval(() => {
            if (document.visibilityState === "visible") void refresh();
        }, 60000);
        return () => {
            channel.close();
            localeChannel.close();
            window.removeEventListener(LOCALE_UPDATED, changed);
            window.removeEventListener("authorization-changed", changed);
            document.removeEventListener("visibilitychange", visible);
            clearInterval(timer);
            window.removeEventListener("session-expired", reset);
            window.removeEventListener("pagehide", hide);
            window.removeEventListener("pageshow", show);
        };
    }, [refresh]);
    return (
        <Context.Provider
            value={{
                identity,
                checking,
                logoutError,
                enrollmentSecret,
                setEnrollmentSecret,
                recoveryCodes,
                setRecoveryCodes,
                refresh,
                logout,
            }}
        >
            {children}
        </Context.Provider>
    );
}
export const useAuth = () => useContext(Context);
export { authResult };
