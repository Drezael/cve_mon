import { t, localized, useLocale } from "../i18n";
import { Routes, Route, Link, Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../auth";
import { Users, UserDetail, Roles } from "./Users";
import { Preferences, Rules, Templates } from "./Notifications";
import { Account, Audit } from "./Account";
import SMTPSettings from "./SMTP";
import AnsibleVault from "./AnsibleVault";
import {
    LanguageSettings,
    InstanceLanguageSettings,
} from "../settings/Language";
const personalLinks = localized([
    ["preferences", "Benachrichtigungspräferenzen", "notification:read"],
    ["mail", "Meine Mail-Einstellungen", "notification:read"],
    ["language", "Sprache", ""],
    ["account", "Kontosicherheit", ""],
    ["ansible-vault", "Mein Ansible-Vault", ""],
]);
const instanceLinks = localized([
    ["instance", "Instanzeinstellungen", "instance:settings:manage"],
    ["users", "Benutzer", "user:list"],
    ["roles", "Rollen", "role:list"],
    ["smtp", "Zentrale SMTP-Einstellungen", "notification:smtp:manage"],
    ["rules", "Versandregeln", "notification:rule:read"],
    ["templates", "Vorlagen", "notification:template:read"],
    ["audit", "Audit", "audit:read"],
]);
export function LegacyAdministrationRedirect() {
    const location = useLocation();
    return (
        <Navigate
            replace
            to={
                "/settings" +
                location.pathname.slice("/administration".length) +
                location.search +
                location.hash
            }
        />
    );
}
export default function Administration() {
    useLocale();
    const { identity } = useAuth();
    const location = useLocation();
    const base = "/settings/";
    const path = location.pathname.split("/")[2] ?? "";
    const links = [...personalLinks, ...instanceLinks];
    const visible = links.filter(
        ([, , permission]) =>
            !permission || identity?.permissions.includes(permission),
    );
    const section = links.find(([part]) => part === path);
    const detailAllowed =
        path !== "users" ||
        location.pathname.split("/").filter(Boolean).length < 3 ||
        identity?.permissions.includes("user:read");
    const allowed =
        (!path || (section && visible.includes(section))) && detailAllowed;
    if (!allowed) {
        return (
            <section role="alert">
                <h1>{t("Zugriff nicht erlaubt")}</h1>
                <p>
                    {t("Für diesen Verwaltungsbereich fehlt die Berechtigung.")}
                </p>
            </section>
        );
    }
    return (
        <>
            <nav className="admin-nav" aria-label={t("Einstellungen")}>
                {visible.map(([part, name]) => (
                    <Link key={part} to={base + part}>
                        {name}
                    </Link>
                ))}
            </nav>
            <Routes>
                <Route
                    index
                    element={
                        <Navigate
                            replace
                            to={base + (visible[0]?.[0] ?? "account")}
                        />
                    }
                />
                <>
                    <Route path="preferences" element={<Preferences />} />
                    <Route path="mail" element={<SMTPSettings personal />} />
                    <Route path="language" element={<LanguageSettings />} />
                    <Route path="account" element={<Account />} />
                    <Route path="ansible-vault" element={<AnsibleVault />} />

                    <Route
                        path="instance"
                        element={<InstanceLanguageSettings />}
                    />
                    <Route path="users" element={<Users />} />
                    <Route path="users/:id" element={<UserDetail />} />
                    <Route path="roles" element={<Roles />} />
                    <Route path="smtp" element={<SMTPSettings />} />
                    <Route path="rules" element={<Rules />} />
                    <Route path="templates" element={<Templates />} />
                    <Route path="audit" element={<Audit />} />
                </>
                <Route
                    path="*"
                    element={<h1>{t("Seite nicht gefunden")}</h1>}
                />
            </Routes>
        </>
    );
}
