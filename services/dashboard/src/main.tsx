import { t, useLocale } from "./i18n";
import { StrictMode, Suspense, lazy, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
    createBrowserRouter,
    RouterProvider,
    Routes,
    Route,
    Navigate,
    NavLink,
    useLocation,
} from "react-router-dom";
import {
    ShieldCheck,
    LayoutDashboard,
    ChartNoAxesCombined,
    Activity,
    Settings2,
    Server,
    Layers,
    ListChecks,
    LogOut,
    Menu,
} from "lucide-react";
import { AuthProvider, useAuth } from "./auth";
import Login from "./pages/Login";
import FindingCountBadge from "./FindingCountBadge";
import { refreshFindingNavigation } from "./finding-refresh";
import { Activation } from "./admin/Account";
import "./style.css";
const StatusPage = lazy(() => import("./status"));
const Administration = lazy(() => import("./admin"));
const LegacyAdministration = lazy(() =>
    import("./admin").then((m) => ({
        default: m.LegacyAdministrationRedirect,
    })),
);
const InventoryManagement = lazy(() => import("./InventoryManagement"));
const Dashboards = lazy(() => import("./dashboards"));
const CustomDashboard = lazy(() =>
    import("./dashboards").then((m) => ({ default: m.DashboardDetail })),
);
const DashboardEditor = lazy(() =>
    import("./dashboards").then((m) => ({ default: m.DashboardEditorPage })),
);
const Overview = lazy(() => import("./pages/Overview"));
const Servers = lazy(() => import("./pages/Servers"));
const ServerDetail = lazy(() =>
    import("./pages/Servers").then((m) => ({ default: m.ServerDetail })),
);
const Groups = lazy(() =>
    import("./pages/Servers").then((m) => ({ default: m.Groups })),
);
const GroupDetail = lazy(() =>
    import("./pages/Servers").then((m) => ({ default: m.GroupDetail })),
);
const Findings = lazy(() => import("./pages/Findings"));
const FindingDetail = lazy(() =>
    import("./pages/Findings").then((m) => ({ default: m.FindingDetail })),
);
const Notifications = lazy(() => import("./pages/Notifications"));
const NotificationDetail = lazy(() =>
    import("./pages/Notifications").then((m) => ({
        default: m.NotificationDetail,
    })),
);
function App() {
    const locale = useLocale();
    const { identity, checking, logout, recoveryCodes } = useAuth();
    const location = useLocation();
    const [menu, setMenu] = useState(false);
    const main = useRef<HTMLElement>(null);
    useEffect(() => {
        setMenu(false);
        main.current?.focus();
    }, [location.pathname]);
    useEffect(() => {
        document.title = t("CVE Monitor · Sicherheitsübersicht");
    }, [locale]);
    if (checking)
        return (
            <main className="auth" role="status">
                {t("Sitzung wird geprüft …")}
            </main>
        );
    if (
        location.pathname === "/activate" &&
        identity?.state !== "authenticated"
    )
        return <Activation />;
    if (
        (recoveryCodes.length > 0 &&
            !["/administration/account", "/settings/account"].includes(
                location.pathname,
            )) ||
        !identity ||
        identity.state !== "authenticated"
    )
        return <Login />;
    const permissions = identity.permissions;
    const nav = [
        {
            path: "/dashboards",
            name: t("Dashboards"),
            icon: LayoutDashboard,
            permission: "server:read",
        },
        {
            path: "/dashboard",
            name: t("Übersicht"),
            icon: ChartNoAxesCombined,
            permission: "security:overview:read",
        },
        {
            path: "/servers",
            name: t("Server"),
            icon: Server,
            permission: "server:read",
        },
        {
            path: "/groups",
            name: t("Gruppen"),
            icon: Layers,
            permission: "server:read",
        },
        {
            path: "/findings",
            name: t("Findings"),
            icon: ListChecks,
            permission: "finding:read",
        },
        {
            path: "/settings",
            name: t("Einstellungen"),
            icon: Settings2,
            permission: "",
        },
        {
            path: "/status",
            name: t("Systemstatus"),
            icon: Activity,
            permission: "deployment:status:read",
        },
    ];
    return (
        <>
            <a className="skip" href="#main">
                {t("Zum Inhalt springen")}
            </a>
            <button
                className="mobile-menu"
                aria-label={t("Navigation öffnen")}
                aria-expanded={menu}
                onClick={() => setMenu(!menu)}
            >
                <Menu />
            </button>
            <aside className={menu ? "sidebar is-open" : "sidebar"}>
                <div className="brand">
                    <ShieldCheck size={31} />
                    <div>
                        {t("CVE")} <strong>{t("MONITOR")}</strong>
                        <small>{t("Security Operations")}</small>
                    </div>
                </div>
                <nav aria-label={t("Hauptnavigation")}>
                    {nav
                        .filter(
                            (n) =>
                                (!n.permission ||
                                    permissions.includes(n.permission)) &&
                                (n.path !== "/status" ||
                                    identity.roles.includes("admin")),
                        )
                        .map((n) => (
                            <NavLink
                                key={n.path}
                                to={n.path}
                                onClick={(event) => {
                                    if (
                                        n.path === "/findings" &&
                                        refreshFindingNavigation(
                                            event,
                                            location.pathname,
                                        )
                                    )
                                        setMenu(false);
                                }}
                            >
                                <n.icon size={19} />
                                {n.name}
                                {n.path === "/findings" && (
                                    <FindingCountBadge />
                                )}
                            </NavLink>
                        ))}
                </nav>
                <div className="sidebar-user">
                    <span>{identity.display_name ?? t("Angemeldet")}</span>
                    <button onClick={() => void logout()}>
                        <LogOut size={17} />
                        {t("Abmelden")}
                    </button>
                </div>
            </aside>
            <div className="workspace">
                <main
                    key={identity.privateKey}
                    id="main"
                    tabIndex={-1}
                    ref={main}
                >
                    <nav
                        className="breadcrumbs"
                        aria-label={t("Brotkrümelnavigation")}
                    >
                        <span>
                            {nav.find(
                                (n) =>
                                    location.pathname === n.path ||
                                    location.pathname.startsWith(n.path + "/"),
                            )?.name ?? t("Ansicht")}
                        </span>
                        {location.pathname.split("/").length > 2 && (
                            <span> {t("/ Details")}</span>
                        )}
                    </nav>
                    <Suspense
                        fallback={
                            <p role="status">{t("Ansicht wird geladen …")}</p>
                        }
                    >
                        <Routes>
                            <Route
                                path="/settings/*"
                                element={<Administration />}
                            />
                            <Route path="/status/*" element={<StatusPage />} />
                            <Route
                                path="/administration/*"
                                element={<LegacyAdministration />}
                            />
                            <Route
                                path="/"
                                element={
                                    <Navigate
                                        replace
                                        to={
                                            permissions.includes(
                                                "security:overview:read",
                                            )
                                                ? "/dashboard"
                                                : "/servers"
                                        }
                                    />
                                }
                            />
                            <Route
                                path="/login"
                                element={<Navigate replace to="/" />}
                            />
                            <Route path="/dashboard" element={<Overview />} />
                            <Route
                                path="/dashboards"
                                element={<Dashboards />}
                            />
                            <Route
                                path="/dashboards/new"
                                element={<DashboardEditor />}
                            />
                            <Route
                                path="/dashboards/:id/edit"
                                element={<DashboardEditor />}
                            />
                            <Route
                                path="/dashboards/:id"
                                element={<CustomDashboard />}
                            />
                            <Route
                                path="/servers/new"
                                element={<InventoryManagement area="create" />}
                            />
                            <Route
                                path="/servers/upload"
                                element={<InventoryManagement area="upload" />}
                            />
                            <Route
                                path="/servers/manage/*"
                                element={<InventoryManagement area="servers" />}
                            />
                            <Route
                                path="/servers/order"
                                element={<InventoryManagement area="order" />}
                            />
                            <Route
                                path="/servers/access/:id"
                                element={<InventoryManagement area="access" />}
                            />
                            <Route
                                path="/groups/manage/*"
                                element={<Groups />}
                            />
                            <Route
                                path="/findings/:id/edit"
                                element={
                                    <InventoryManagement area="findings" />
                                }
                            />
                            <Route path="/servers" element={<Servers />} />
                            <Route
                                path="/servers/:id"
                                element={<ServerDetail />}
                            />
                            <Route path="/groups" element={<Groups />} />
                            <Route
                                path="/groups/:id"
                                element={<GroupDetail />}
                            />
                            <Route path="/findings" element={<Findings />} />
                            <Route
                                path="/findings/:id"
                                element={<FindingDetail />}
                            />
                            <Route
                                path="/notifications"
                                element={<Notifications />}
                            />
                            <Route
                                path="/notifications/:id"
                                element={<NotificationDetail />}
                            />
                            <Route
                                path="*"
                                element={
                                    <>
                                        <h1>{t("Seite nicht gefunden")}</h1>
                                        <p>
                                            {t(
                                                "Diese Adresse ist nicht verfügbar.",
                                            )}
                                        </p>
                                        <NavLink to="/">
                                            {t("Zur Übersicht")}
                                        </NavLink>
                                    </>
                                }
                            />
                        </Routes>
                    </Suspense>
                </main>
                <footer>
                    {t(
                        "Stand der Daten gemäß letzter erfolgreicher Verarbeitung · CVE Monitor",
                    )}
                </footer>
            </div>
        </>
    );
}
createRoot(document.getElementById("root")!).render(
    <StrictMode>
        <AuthProvider>
            <RouterProvider
                router={createBrowserRouter([{ path: "*", element: <App /> }])}
            />
        </AuthProvider>
    </StrictMode>,
);
