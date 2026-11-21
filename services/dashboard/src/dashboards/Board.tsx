import { createContext, useContext, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { t, useLocale } from "../i18n";
import { useAuth } from "../auth";
import { useData, State, Card, Badge, Distribution, Facts } from "../ui";
import {
    overviewSchema,
    serverSchema,
    findingSchema,
    page,
} from "../contracts";
import CveDataStatus from "../pages/CveDataStatus";
import WorkflowControl from "../pages/WorkflowControl";
import FindingTrend from "../pages/FindingTrend";
import { ApiError } from "../api";
import { number, date } from "../format";
import { type DashboardConfig, type Widget, widgetQuery } from "./contracts";

const serversSchema = page(serverSchema);
const findingsSchema = page(findingSchema);
const Summary = createContext<ReturnType<
    typeof useData<ReturnType<typeof overviewSchema.parse>>
> | null>(null);
function SummaryProvider({
    interval,
    children,
}: {
    interval: number;
    children: ReactNode;
}) {
    const data = useData("/api/v1/dashboard/overview", overviewSchema, {
        refreshInterval: interval,
    });
    return <Summary.Provider value={data}>{children}</Summary.Provider>;
}
export default function Board({ config }: { config: DashboardConfig }) {
    useLocale();
    const { identity } = useAuth();
    return <DashboardView key={identity?.privateKey} config={config} />;
}
function DashboardView({ config }: { config: DashboardConfig }) {
    const { identity } = useAuth();
    const permissions = identity?.permissions ?? [];
    const interval = config.refresh_interval_seconds * 1000;
    let tableSlot = 0;
    const widgets = (
        <div
            className={`custom-dashboard-grid columns-${config.layout.columns}`}
        >
            {config.widgets.map((widget) => {
                const delay =
                    widget.type === "servers" || widget.type === "findings"
                        ? tableSlot++ * 600
                        : 0;
                const permission =
                    widget.type === "text"
                        ? null
                        : widget.type === "database" ||
                            widget.type === "workflow"
                          ? "cve:read"
                          : widget.type === "servers"
                            ? "server:read"
                            : widget.type === "findings"
                              ? "finding:read"
                              : "security:overview:read";
                return (
                    <div
                        className={`dashboard-widget span-${widget.span}`}
                        key={widget.id}
                    >
                        {(permission && !permissions.includes(permission)) ||
                        (["database", "workflow"].includes(widget.type) &&
                            !identity?.roles?.includes("admin")) ? (
                            <Card title={widget.title}>
                                <p>
                                    {t("Keine Berechtigung für dieses Widget.")}
                                </p>
                            </Card>
                        ) : (
                            <WidgetView
                                widget={widget}
                                interval={interval}
                                delay={delay}
                            />
                        )}
                    </div>
                );
            })}
        </div>
    );
    return config.widgets.some((w) =>
        ["metric", "distribution", "summary", "inventory_quality"].includes(
            w.type,
        ),
    ) && permissions.includes("security:overview:read") ? (
        <SummaryProvider interval={interval}>{widgets}</SummaryProvider>
    ) : (
        widgets
    );
}
function WidgetView({
    widget,
    interval,
    delay,
}: {
    widget: Widget;
    interval: number;
    delay: number;
}) {
    useLocale();
    const summary = useContext(Summary);
    if (widget.type === "database") return <CveDataStatus />;
    if (widget.type === "workflow") return <WorkflowControl />;
    if (widget.type === "trend")
        return (
            <FindingTrend
                initialDays={widget.days}
                interval={interval}
                title={widget.title}
            />
        );

    if (widget.type === "servers")
        return (
            <ServerWidget widget={widget} interval={interval} delay={delay} />
        );
    if (widget.type === "findings")
        return (
            <FindingWidget widget={widget} interval={interval} delay={delay} />
        );
    if (widget.type === "text")
        return (
            <Card title={widget.title}>
                <p className="dashboard-note">{widget.text}</p>
            </Card>
        );
    if (
        summary?.error instanceof ApiError &&
        [401, 403, 404].includes(summary.error.status)
    )
        return (
            <Card title={widget.title}>
                <State error={summary.error} reload={summary.reload} />
            </Card>
        );
    if (!summary?.data)
        return (
            <Card title={widget.title}>
                {summary && (
                    <State error={summary.error} reload={summary.reload} />
                )}
            </Card>
        );
    if (widget.type === "summary")
        return (
            <Card title={widget.title}>
                <p className="muted">
                    {t("Stand")}: {date(summary.data.generated_at)}
                </p>
                <div className="kpis">
                    {[
                        [t("Aktive Server"), summary.data.active_servers],
                        [t("Offene Findings"), summary.data.open_findings],
                        [t("Betroffene Server"), summary.data.servers_affected],
                        [t("Überfällige Findings"), summary.data.overdue],
                    ].map(([name, value]) => (
                        <section key={String(name)}>
                            <h3>{name}</h3>
                            <strong className="dashboard-metric">
                                {number(value)}
                            </strong>
                        </section>
                    ))}
                </div>
                <p>
                    {t("Kritisch:")} {number(summary.data.critical)} ·{" "}
                    {t("Hoch")}: {number(summary.data.high)} · {t("Betroffen")}:{" "}
                    {number(
                        (summary.data.technical.affected ?? 0) +
                            (summary.data.technical.potentially_affected ?? 0),
                    )}{" "}
                    · {t("Nicht bewertbar")}: {number(summary.data.unknown)} ·
                    KEV: {number(summary.data.kev)}
                </p>
            </Card>
        );
    if (widget.type === "inventory_quality")
        return (
            <Card title={widget.title}>
                {summary.data.inventory_data_available ? (
                    <Facts values={summary.data.inventory} />
                ) : (
                    <p>{t("Keine Berechtigung für dieses Widget.")}</p>
                )}
            </Card>
        );
    if (widget.type === "metric")
        return (
            <Card title={widget.title}>
                <strong className="dashboard-metric">
                    {number(summary.data[widget.metric])}
                </strong>
                {summary.error && (
                    <p role="status">
                        {t(
                            "Aktualisierung fehlgeschlagen. Der letzte Stand bleibt sichtbar.",
                        )}
                    </p>
                )}
            </Card>
        );
    if (widget.type !== "distribution") return null;
    if (
        (widget.source === "inventory" &&
            !summary.data.inventory_data_available) ||
        (["priorities", "lifecycle", "technical", "kev_priorities"].includes(
            widget.source,
        ) &&
            !summary.data.finding_data_available)
    )
        return (
            <Card title={widget.title}>
                <p>{t("Keine Berechtigung für dieses Widget.")}</p>
            </Card>
        );
    const values = Object.fromEntries(
        Object.entries(summary.data[widget.source]).filter(
            (entry): entry is [string, number] => typeof entry[1] === "number",
        ),
    );
    if (widget.source === "technical") {
        values.affected =
            (values.affected ?? 0) + (values.potentially_affected ?? 0);
        delete values.potentially_affected;
    }
    return <Distribution title={widget.title} values={values} />;
}
function ServerWidget({
    widget,
    interval,
    delay,
}: {
    widget: Extract<Widget, { type: "servers" }>;
    interval: number;
    delay: number;
}) {
    useLocale();
    const query = widgetQuery(widget.filters, widget.limit);
    query.set("sort", widget.sort);
    const result = useData(
        `/api/v1/dashboard/security/servers?${query}`,
        serversSchema,
        { refreshInterval: interval, initialDelay: delay },
    );
    return (
        <Card title={widget.title}>
            {!result.data ||
            (result.error instanceof ApiError &&
                [401, 403, 404].includes(result.error.status)) ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    {result.error && (
                        <p role="status">
                            {t(
                                "Aktualisierung fehlgeschlagen. Der letzte Stand bleibt sichtbar.",
                            )}
                        </p>
                    )}
                    <div className="table-scroll">
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("Server")}</th>
                                    <th>{t("Status")}</th>
                                    <th>{t("Offene Findings")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {result.data.items.map((s) => (
                                    <tr key={s.id}>
                                        <td>
                                            <Link to={`/servers/${s.id}`}>
                                                {s.display_name}
                                            </Link>
                                        </td>
                                        <td>
                                            <Badge value={s.status} />
                                        </td>
                                        <td>{number(s.open_findings)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    <p>
                        {t("{0} von {1} Einträgen", [
                            result.data.items.length,
                            result.data.total,
                        ])}
                    </p>
                    <Link to={`/servers?${query}`}>{t("Alle anzeigen")}</Link>
                </>
            )}
        </Card>
    );
}
function FindingWidget({
    widget,
    interval,
    delay,
}: {
    widget: Extract<Widget, { type: "findings" }>;
    interval: number;
    delay: number;
}) {
    useLocale();
    const query = widgetQuery(widget.filters, widget.limit);
    const result = useData(`/api/v1/findings?${query}`, findingsSchema, {
        refreshInterval: interval,
        initialDelay: delay,
    });
    return (
        <Card title={widget.title}>
            {!result.data ||
            (result.error instanceof ApiError &&
                [401, 403, 404].includes(result.error.status)) ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    {result.error && (
                        <p role="status">
                            {t(
                                "Aktualisierung fehlgeschlagen. Der letzte Stand bleibt sichtbar.",
                            )}
                        </p>
                    )}
                    <div className="table-scroll">
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("CVE")}</th>
                                    <th>{t("Server")}</th>
                                    <th>{t("Priorität")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {result.data.items.map((f) => (
                                    <tr key={f.id}>
                                        <td>
                                            <Link to={`/findings/${f.id}`}>
                                                {f.cve_id}
                                            </Link>
                                        </td>
                                        <td>{f.server_name}</td>
                                        <td>
                                            <Badge value={f.current_priority} />
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    <p>
                        {t("{0} von {1} Einträgen", [
                            result.data.items.length,
                            result.data.total,
                        ])}
                    </p>
                    <Link to={`/findings?${query}`}>{t("Alle anzeigen")}</Link>
                </>
            )}
        </Card>
    );
}
