import { t, useLocale } from "./i18n";
import { Link, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import { Resources, ResourceDetail } from "./admin/Resources";
import { Access } from "./admin/Users";
import Ordering from "./admin/Ordering";
import Upload from "./admin/Upload";
import FindingManagement from "./admin/Findings";
import ServerCreation, { CreateServerButton } from "./ServerCreation";

type Area = "servers" | "upload" | "create" | "order" | "access" | "findings";

export default function InventoryManagement({ area }: { area: Area }) {
    useLocale();
    const { identity } = useAuth();
    const permissions = identity?.permissions ?? [];
    const required = {
        servers: ["server:read"],
        upload: ["server:inventory:manage"],
        create: ["server:create", "server:inventory:manage"],
        order: ["server:reorder"],
        access: ["server:acl:manage"],
        findings: ["finding:update"],
    }[area];
    if (!required.some((permission) => permissions.includes(permission))) {
        return (
            <section role="alert">
                <h1>{t("Zugriff nicht erlaubt")}</h1>
                <p>{t("Für diesen Bereich fehlt die Berechtigung.")}</p>
            </section>
        );
    }
    return (
        <>
            <nav className="admin-nav" aria-label={t("Bestandsverwaltung")}>
                <Link to={area === "findings" ? "/findings" : "/servers"}>
                    {t("Zur Übersicht")}
                </Link>
                {area !== "findings" && (
                    <>
                        {area !== "servers" && area !== "create" && (
                            <CreateServerButton />
                        )}
                        {required.includes("server:read") &&
                            permissions.includes("server:reorder") && (
                                <Link to="/servers/order">
                                    {t("Reihenfolge")}
                                </Link>
                            )}
                    </>
                )}
            </nav>
            {area === "servers" ? (
                <Routes>
                    <Route index element={<Resources />} />
                    <Route path=":id" element={<ResourceDetail />} />
                    <Route
                        path="*"
                        element={<h1>{t("Seite nicht gefunden")}</h1>}
                    />
                </Routes>
            ) : area === "create" ? (
                <ServerCreation />
            ) : area === "upload" ? (
                <Upload />
            ) : area === "order" ? (
                <Ordering />
            ) : area === "access" ? (
                <Access />
            ) : (
                <FindingManagement />
            )}
        </>
    );
}
