import { AssignServerGroups } from "../ServerGroups";
import { t, useLocale } from "../i18n";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useData, State, Badge, Pagination, Card } from "../ui";
import { row, listing, version, text, type Row } from "./contracts";
import { EditForm } from "./Form";
import AnsibleSettings from "./AnsibleSettings";
import DeleteServer from "../DeleteServer";
import { serverFields } from "./serverFields";
import { serverSchema } from "../contracts";
import { CreateServerButton } from "../ServerCreation";
const base = "/api/v1/dashboard/admin/";
export function Resources() {
    const kind = "servers";
    useLocale();
    const [search, setSearch] = useState("");
    const [query, setQuery] = useState("");
    const [status, setStatus] = useState("active");
    const [offset, setOffset] = useState(0);
    const result = useData(
        `${base}${kind}?${new URLSearchParams({ search: query, status, limit: "25", offset: String(offset) })}`,
        listing,
    );
    return (
        <>
            <h1>{t("Serververwaltung")}</h1>
            <p>
                {t(
                    "Registrierte Identitäten und gespeicherte Verwaltungsdaten. Die optionale automatische Erfassung kann pro Server eingerichtet werden.",
                )}
            </p>
            <div className="filters">
                <label>
                    {t("Suche")}
                    <input
                        value={search}
                        maxLength={128}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </label>
                <button
                    onClick={() => {
                        setQuery(search);
                        setOffset(0);
                    }}
                >
                    {t("Suchen")}
                </button>
                <label>
                    {t("Status")}
                    <select
                        value={status}
                        onChange={(e) => {
                            setStatus(e.target.value);
                            setOffset(0);
                        }}
                    >
                        <option value="active">{t("Aktiv")}</option>
                        <option value="archived">{t("Archiviert")}</option>
                    </select>
                </label>
                <CreateServerButton />
            </div>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <Card title={t("Bestand")}>
                    <div className="table-scroll">
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("Bezeichnung")}</th>
                                    <th>{t("Status")}</th>
                                    <th>{t("Version")}</th>
                                    <th>{t("Aktion")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {result.data.items.map((r) => (
                                    <tr key={text(r, "id")}>
                                        <td>
                                            {text(r, "display_name")}
                                            <small>{text(r, "id")}</small>
                                        </td>
                                        <td>
                                            <Badge value={r.status} />
                                        </td>
                                        <td>{String(r.version)}</td>
                                        <td>
                                            <Link
                                                to={`/${kind}/manage/${text(r, "id")}`}
                                            >
                                                {t("Verwalten")}
                                            </Link>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {result.data.total === 0 && <p>{t("Keine Einträge.")}</p>}
                    <Pagination
                        offset={offset}
                        total={result.data.total}
                        onChange={setOffset}
                    />
                </Card>
            )}
        </>
    );
}
export function ResourceDetail() {
    useLocale();
    const { id = "" } = useParams();
    const access = useData(
        "/api/v1/dashboard/security/servers/" + id,
        serverSchema,
    );
    if (!access.data)
        return <State error={access.error} reload={access.reload} />;
    if (!access.data.can_edit)
        return <p role="alert">{t("Keine Berechtigung.")}</p>;
    return <ServerEditorLoader id={id} />;
}
function ServerEditorLoader({ id }: { id: string }) {
    const result = useData(base + "servers/" + id, row);
    const navigate = useNavigate();
    if (!result.data)
        return <State error={result.error} reload={result.reload} />;
    return (
        <ServerEdit
            key={id}
            server={result.data}
            onExit={() => navigate("/servers")}
        />
    );
}
function ServerEdit({ server, onExit }: { server: Row; onExit: () => void }) {
    useLocale();
    const id = text(server, "id");
    return (
        <>
            <h1>{text(server, "display_name")}</h1>
            <EditForm
                operation={{
                    title: t("Server bearbeiten"),
                    path: base + "servers/" + id,
                    method: "PATCH",
                    fields: serverFields,
                    version: version(server),
                    initial: server,
                    payload: (v) =>
                        Object.fromEntries(
                            serverFields.map((f) => [
                                f.key,
                                v[f.key] ||
                                    (["description", "environment"].includes(
                                        f.key,
                                    )
                                        ? null
                                        : v[f.key]),
                            ]),
                        ),
                }}
                onCancel={onExit}
                onDone={onExit}
                onReload={onExit}
            />
            <details>
                <summary>{t("Weitere Servereinstellungen")}</summary>
                <AssignServerGroups
                    server={id}
                    name={text(server, "display_name")}
                    onSaved={() => {}}
                />
                <AnsibleSettings server={id} />
                <DeleteServer
                    server={{
                        id,
                        display_name: text(server, "display_name"),
                        version: version(server),
                        can_delete: true,
                    }}
                    onDeleted={onExit}
                />
            </details>
        </>
    );
}
