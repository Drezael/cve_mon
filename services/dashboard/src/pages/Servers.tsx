import { t, useLocale } from "../i18n";
import { useState } from "react";
import {
    Link,
    useNavigate,
    useParams,
    useSearchParams,
} from "react-router-dom";
import { serverSchema, page } from "../contracts";
import { useData, State, Pagination, Badge, Card, Facts } from "../ui";
import { useAuth } from "../auth";
import ContainerInventory from "../ContainerInventory";
import { CreateServerButton } from "../ServerCreation";
import ScanServer from "../ScanServer";
import { ServerGroups, useServerGroups } from "../ServerGroups";
import { Fragment } from "react";
import { number, label } from "../format";
const serversSchema = page(serverSchema);
export default function Servers() {
    useLocale();
    const { identity } = useAuth();
    const navigate = useNavigate();
    const groups = useServerGroups();
    const [distribution, setDistribution] = useState("");
    const [params, setParams] = useSearchParams();
    const offset = Number(params.get("offset")) || 0;
    const [search, setSearch] = useState(params.get("search") ?? "");
    const request = new URLSearchParams(params);
    request.set("limit", "25");
    const result = useData(
        `/api/v1/dashboard/security/servers?${request}`,
        serversSchema,
    );
    const items = result.data?.items ?? [];
    const sections = groups.data?.items.length
        ? [
              ...groups.data.items
                  .filter(
                      (g) =>
                          !params.get("group_id") ||
                          params.get("group_id") === g.id,
                  )
                  .map((g) => ({
                      id: g.id,
                      name: g.name,
                      servers: items.filter((s) =>
                          s.groups.some((m) => m.id === g.id),
                      ),
                  })),
              {
                  id: "ungrouped",
                  name: t("Ohne Gruppe"),
                  servers: items.filter((s) => !s.groups.length),
              },
          ].filter((g) => g.servers.length)
        : [{ id: "all", name: "", servers: items }];
    return (
        <>
            <header className="page-header">
                <div>
                    <p className="eyebrow">{t("INVENTAR & RISIKEN")}</p>
                    <h1>{t("Server")}</h1>
                    <p>
                        {t(
                            "Bestand und Datenqualität Ihrer freigegebenen Systeme",
                        )}
                    </p>
                </div>
                <div className="actions">
                    <CreateServerButton />
                    <button onClick={() => navigate("/groups")}>
                        {t("Gruppen")}
                    </button>
                    <button
                        onClick={() => {
                            result.reload();
                            groups.reload();
                        }}
                    >
                        {t("Aktualisieren")}
                    </button>
                </div>
            </header>
            <form
                className="filters"
                onSubmit={(e) => {
                    e.preventDefault();
                    params.set("search", search);
                    if (distribution) params.set("distribution", distribution);
                    else params.delete("distribution");
                    params.delete("offset");
                    setParams(params);
                }}
            >
                <label>
                    {t("Server suchen")}
                    <input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        maxLength={120}
                        placeholder={t("Anzeigename")}
                    />
                </label>
                <label>
                    {t("Sortierung")}
                    <select
                        value={params.get("sort") ?? "manual"}
                        onChange={(e) => {
                            params.set("sort", e.target.value);
                            params.delete("offset");
                            setParams(params);
                        }}
                    >
                        <option value="manual">
                            {t("Manuelle Reihenfolge")}
                        </option>
                        <option value="name">{t("Name")}</option>
                        <option value="inventory">
                            {t("Inventarzeitpunkt")}
                        </option>
                    </select>
                </label>
                <label>
                    {t("Gruppe")}
                    <select
                        value={params.get("group_id") ?? ""}
                        onChange={(e) => {
                            if (e.target.value)
                                params.set("group_id", e.target.value);
                            else params.delete("group_id");
                            params.delete("offset");
                            setParams(params);
                        }}
                    >
                        <option value="">{t("Alle sichtbaren Gruppen")}</option>
                        {groups.data?.items.map((g) => (
                            <option key={g.id} value={g.id}>
                                {g.name}
                            </option>
                        ))}
                    </select>
                </label>
                <label>
                    {t("Distribution")}
                    <input
                        value={distribution}
                        maxLength={128}
                        onChange={(e) => setDistribution(e.target.value)}
                        placeholder={t("Exakter Distributionsname")}
                    />
                </label>
                {identity?.permissions.includes("server:archive") && (
                    <label>
                        {t("Archivstatus")}
                        <select
                            value={params.get("status") ?? "active"}
                            onChange={(e) => {
                                params.set("status", e.target.value);
                                params.delete("offset");
                                setParams(params);
                            }}
                        >
                            <option value="active">{t("Aktiv")}</option>
                            <option value="archived">{t("Archiviert")}</option>
                        </select>
                    </label>
                )}
                <button type="submit">{t("Suchen")}</button>
            </form>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <div className="card">
                    {!!groups.data?.items.length && (
                        <p className="muted">
                            {t(
                                "Gruppierung der aktuellen Seite. Server mit mehreren Gruppen erscheinen in jeder zugeordneten Gruppe.",
                            )}
                        </p>
                    )}
                    <div
                        className="table-scroll"
                        tabIndex={0}
                        role="region"
                        aria-label={t("Scrollbare Tabelle")}
                    >
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("Server")}</th>
                                    <th>{t("Gruppen")}</th>
                                    <th>{t("Status")}</th>
                                    <th>{t("Distribution / Kernel")}</th>
                                    <th>{t("Inventar")}</th>
                                    <th>{t("Offene Findings")}</th>
                                    <th>{t("Höchste Priorität")}</th>
                                    <th>{t("Aktionen")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {sections.map((section) => (
                                    <Fragment key={section.id}>
                                        {section.name && (
                                            <tr className="server-group-heading">
                                                <th
                                                    colSpan={8}
                                                    scope="colgroup"
                                                >
                                                    {section.name}
                                                </th>
                                            </tr>
                                        )}
                                        {section.servers.map((s) => (
                                            <tr key={s.id}>
                                                <td>
                                                    <Link
                                                        to={`/servers/${s.id}${s.status === "archived" ? "?archived=true" : ""}`}
                                                    >
                                                        {s.display_name}
                                                    </Link>
                                                    <small>{s.id}</small>
                                                </td>
                                                <td>
                                                    {s.groups.map((g) => (
                                                        <div key={g.id}>
                                                            <Link
                                                                to={`/servers?group_id=${g.id}`}
                                                            >
                                                                {g.name}
                                                            </Link>
                                                        </div>
                                                    ))}
                                                </td>
                                                <td>
                                                    <Badge value={s.status} />
                                                </td>
                                                <td>
                                                    {String(
                                                        s.inventory
                                                            ?.distribution ??
                                                            t("Unbekannt"),
                                                    )}
                                                    <small>
                                                        {String(
                                                            s.inventory
                                                                ?.kernel_version ??
                                                                t(
                                                                    "Kernel unbekannt",
                                                                ),
                                                        )}
                                                    </small>
                                                </td>
                                                <td>
                                                    {s.inventory ? (
                                                        <Badge
                                                            value={
                                                                s.inventory
                                                                    .inventory_freshness
                                                            }
                                                        />
                                                    ) : (
                                                        <span>
                                                            {t(
                                                                "Nicht verfügbar",
                                                            )}
                                                        </span>
                                                    )}
                                                    {s.inventory
                                                        ?.latest_snapshot_id &&
                                                    (s.inventory
                                                        .collection_status !==
                                                        "complete" ||
                                                        s.inventory
                                                            .processing_status !==
                                                            "processed") ? (
                                                        <small className="inventory-warning">
                                                            {t(
                                                                "Letzter Versuch:",
                                                            )}{" "}
                                                            {label(
                                                                s.inventory
                                                                    .collection_status,
                                                            )}{" "}
                                                            ·{" "}
                                                            {label(
                                                                s.inventory
                                                                    .processing_status,
                                                            )}
                                                        </small>
                                                    ) : null}
                                                </td>
                                                <td>
                                                    {number(s.open_findings)}
                                                </td>
                                                <td>
                                                    {s.highest_priority ? (
                                                        <Badge
                                                            value={
                                                                s.highest_priority
                                                            }
                                                        />
                                                    ) : (
                                                        <span>
                                                            {t(
                                                                "Keine Bewertung",
                                                            )}
                                                        </span>
                                                    )}
                                                </td>
                                                <td>
                                                    <div className="actions">
                                                        <button
                                                            disabled={
                                                                !s.can_edit
                                                            }
                                                            onClick={() =>
                                                                navigate(
                                                                    `/servers/manage/${s.id}`,
                                                                )
                                                            }
                                                        >
                                                            {t("Bearbeiten")}
                                                        </button>
                                                        <ScanServer
                                                            id={s.id}
                                                            enabled={s.can_scan}
                                                        />
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </Fragment>
                                ))}
                            </tbody>
                        </table>
                        {result.data.total === 0 && (
                            <p className="empty">
                                {t(
                                    "Keine sichtbaren Server für diese Auswahl.",
                                )}
                            </p>
                        )}
                    </div>
                    <Pagination
                        offset={offset}
                        total={result.data.total}
                        onChange={(n) => {
                            params.set("offset", String(n));
                            setParams(params);
                        }}
                    />
                </div>
            )}
        </>
    );
}
export function ServerDetail() {
    useLocale();
    const navigate = useNavigate();
    const { id } = useParams();
    const [params] = useSearchParams();
    const result = useData(
        `/api/v1/dashboard/security/servers/${id}${params.get("archived") === "true" ? "?archived=true" : ""}`,
        serverSchema,
    );
    const s = result.data;
    return (
        <>
            <h1>{s?.display_name ?? t("Serverdetails")}</h1>
            {!s ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <p>
                        <Badge value={s.status} /> ·{" "}
                        <Link to={`/findings?server_id=${s.id}`}>
                            {t("Findings dieses Servers")}
                        </Link>
                    </p>
                    <div className="actions">
                        <button
                            disabled={!s.can_edit}
                            onClick={() => navigate(`/servers/manage/${s.id}`)}
                        >
                            {t("Bearbeiten")}
                        </button>
                        <ScanServer id={s.id} enabled={s.can_scan} />
                    </div>
                    {s.inventory && (
                        <ContainerInventory key={s.id} server={s.id} />
                    )}
                    <div className="grid-two">
                        <Card title={t("Server")}>
                            <Facts
                                values={{
                                    Umgebung: s.environment,
                                    Kritikalität: s.criticality,
                                    "Offene Findings": s.open_findings,
                                    "Höchste Priorität": s.highest_priority,
                                }}
                            />
                            <h3>{t("Gruppen")}</h3>
                            {s.groups.map((g) => (
                                <p key={g.id}>
                                    <Link to={`/servers?group_id=${g.id}`}>
                                        {g.name}
                                    </Link>
                                </p>
                            ))}
                        </Card>
                        <Card title={t("Inventar & Datenqualität")}>
                            {s.inventory ? (
                                <>
                                    <p>
                                        {t(
                                            "Gespeicherter Snapshot; keine Live-Abfrage des Servers.",
                                        )}
                                    </p>
                                    <Facts values={s.inventory} />
                                </>
                            ) : (
                                <p>
                                    {t(
                                        "Inventardaten sind für Ihre Berechtigung nicht verfügbar.",
                                    )}
                                </p>
                            )}
                        </Card>
                        <Card title={t("Matching")}>
                            <Facts
                                values={
                                    s.matching ?? {
                                        Bewertung: t("Nicht verfügbar"),
                                    }
                                }
                            />
                            <p>
                                {t(
                                    "Fehlende oder veraltete Auswertungen sind keine Entwarnung.",
                                )}
                            </p>
                        </Card>
                    </div>
                </>
            )}
        </>
    );
}
export function Groups() {
    return <ServerGroups />;
}
export function GroupDetail() {
    return <ServerGroups />;
}
