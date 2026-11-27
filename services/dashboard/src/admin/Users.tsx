import { translateMessage, t, localized, useLocale } from "../i18n";
import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useData, State, Card, Facts, Pagination, Badge } from "../ui";
import {
    userCreateSchema,
    row,
    rows,
    listing,
    itemList,
    rolesSchema,
    selected,
    text,
    version,
    type Row,
} from "./contracts";
import {
    Allowed,
    DraftGuard,
    Inputs,
    EditForm,
    reason,
    type Field,
    type Mutation,
} from "./Form";
const base = "/api/v1/dashboard/admin/";
const userFields: Field[] = localized([
    { key: "username", label: "Benutzername", required: true, max: 128 },
    { key: "display_name", label: "Anzeigename", required: true, max: 128 },
    {
        key: "email",
        label: "E-Mail-Adresse",
        type: "email",
        required: true,
        max: 254,
    },
]);
function UserRoleEditor({
    user,
    onClose,
    onSaved,
}: {
    user: Row;
    onClose: () => void;
    onSaved: () => void;
}) {
    useLocale();
    const id = text(user, "id");
    const account = useData(base + "users/" + id, row);
    const roles = useData(
        "/api/v1/dashboard/administration/users/" + id + "/roles",
        itemList,
    );
    const title = t("Rollen für {0} zuweisen", [text(user, "username")]);
    const reload = () => {
        account.reload();
        roles.reload();
    };
    if (!account.data || !roles.data)
        return (
            <Card title={title}>
                <State error={account.error || roles.error} reload={reload} />
                <button onClick={onClose}>{t("Abbrechen")}</button>
            </Card>
        );
    return (
        <EditForm
            operation={{
                title,
                path: base + "users/" + id + "/roles",
                method: "PUT",
                critical: true,
                fields: [
                    {
                        key: "role_ids",
                        label: t("Rollen"),
                        type: "picker",
                        source: base + "roles",
                        arraySource: true,
                        multiple: true,
                    },
                    reason,
                ],
                initial: { role_ids: roles.data.items.map((v) => v.id) },
                payload: (v) => ({ ...v, version: version(account.data!) }),
            }}
            onCancel={onClose}
            onReload={reload}
            onDone={onSaved}
        />
    );
}
export function Users() {
    useLocale();
    const [offset, setOffset] = useState(0);
    const [search, setSearch] = useState("");
    const [query, setQuery] = useState("");
    const result = useData(
        `${base}users?${new URLSearchParams({ search: query, limit: "25", offset: String(offset) })}`,
        listing,
    );
    const [operation, setOperation] = useState<Mutation | null>(null);
    const navigate = useNavigate();
    return (
        <>
            <h1>{t("Benutzerverwaltung")}</h1>
            <p>
                {t(
                    "Neue Konten erhalten die Rolle user und kein voreingestelltes Passwort. Der bestehende sichere Aktivierungsvorgang bleibt erforderlich.",
                )}
            </p>
            <div className="filters">
                <label>
                    {t("Benutzer suchen")}
                    <input
                        maxLength={128}
                        value={search}
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
                <Allowed permission="user:create">
                    <button
                        onClick={() =>
                            setOperation({
                                title: t("Benutzer erstellen"),
                                path: base + "users",
                                method: "POST",
                                fields: userFields,
                                validate: (v) =>
                                    userCreateSchema.safeParse(v).success
                                        ? null
                                        : t(
                                              "Bitte Benutzername, Anzeigename und E-Mail prüfen.",
                                          ),
                            })
                        }
                    >
                        {t("Benutzer erstellen")}
                    </button>
                </Allowed>
            </div>
            {operation && (
                <EditForm
                    operation={operation}
                    onCancel={() => setOperation(null)}
                    onReload={() => {
                        setOperation(null);
                        result.reload();
                    }}
                    onDone={(r) => {
                        setOperation(null);
                        result.reload();
                        if (r) navigate("/settings/users/" + String(r.id));
                    }}
                />
            )}
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <Card title={t("Konten")}>
                    <div
                        className="table-scroll"
                        tabIndex={0}
                        role="region"
                        aria-label={t("Scrollbare Tabelle")}
                    >
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("Benutzer")}</th>
                                    <th>{t("Anzeigename")}</th>
                                    <th>{t("Rollen")}</th>
                                    <th>{t("Status")}</th>
                                    <th>{t("Aktion")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {result.data.items.map((r) => (
                                    <tr key={text(r, "id")}>
                                        <td>{text(r, "username")}</td>
                                        <td>{text(r, "display_name")}</td>
                                        <td>
                                            <div className="user-role-badges">
                                                {selected(r.roles).length ? (
                                                    selected(r.roles).map(
                                                        (role) => (
                                                            <span
                                                                className="badge"
                                                                key={role}
                                                            >
                                                                {role}
                                                            </span>
                                                        ),
                                                    )
                                                ) : (
                                                    <span className="muted">
                                                        {t("Keine Rolle")}
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                        <td>
                                            <Badge value={r.status} />
                                        </td>
                                        <td>
                                            <button
                                                type="button"
                                                onClick={() =>
                                                    navigate(
                                                        `/settings/users/${text(r, "id")}`,
                                                    )
                                                }
                                            >
                                                {t("Benutzer verwalten")}
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
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
export function UserDetail() {
    useLocale();
    const { id = "" } = useParams();
    const result = useData(base + "users/" + id, row);
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [notice, setNotice] = useState("");
    const [editRoles, setEditRoles] = useState(false);
    const r = result.data;
    return (
        <>
            <h1>{r ? text(r, "display_name") : t("Benutzerdetails")}</h1>
            {notice && (
                <p className="notice" role="status">
                    {translateMessage(notice)}
                </p>
            )}
            {!r ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <Card title={t("Konto")}>
                        <Facts
                            values={{
                                ...r,
                                status:
                                    r.status === "pending"
                                        ? t("Aktivierung ausstehend")
                                        : r.status,
                            }}
                        />
                        <div className="actions">
                            <Allowed permission="user:role:assign">
                                <button onClick={() => setEditRoles(true)}>
                                    {t("Rollenzuweisung ändern")}
                                </button>
                            </Allowed>
                            <Allowed permission="user:update">
                                <button
                                    onClick={() =>
                                        setOperation({
                                            title: t(
                                                "Benutzer {0} bearbeiten",
                                                [text(r, "username")],
                                            ),
                                            path: base + "users/" + id,
                                            method: "PATCH",
                                            fields: [
                                                ...userFields.slice(1),
                                                reason,
                                            ],
                                            initial: r,
                                            payload: (v) => ({
                                                display_name: v.display_name,
                                                email: v.email,
                                                version: version(r),
                                                reason: v.reason,
                                            }),
                                        })
                                    }
                                >
                                    {t("Benutzerdaten bearbeiten")}
                                </button>
                            </Allowed>
                            {[
                                ["enable", "user:enable", t("Aktivieren")],
                                ["disable", "user:disable", t("Deaktivieren")],
                                ["lock", "user:disable", t("Konto sperren")],
                                [
                                    "archive",
                                    "user:archive",
                                    t("Konto archivieren"),
                                ],
                                [
                                    "revoke-sessions",
                                    "user:session:revoke",
                                    t("Sitzungen widerrufen"),
                                ],
                                [
                                    "mfa-recovery",
                                    "user:mfa:recovery",
                                    t("MFA-Wiederherstellung anfordern"),
                                ],
                            ].map(([action, permission, title]) => (
                                <Allowed key={action} permission={permission}>
                                    <button
                                        onClick={() =>
                                            setOperation({
                                                title: `${title}: ${text(r, "username")}`,
                                                path:
                                                    base +
                                                    "users/" +
                                                    id +
                                                    "/" +
                                                    action,
                                                method: "POST",
                                                critical: true,
                                                fields: [reason],
                                                payload: (v) => ({
                                                    ...v,
                                                    version: version(r),
                                                }),
                                            })
                                        }
                                    >
                                        {title}
                                    </button>
                                </Allowed>
                            ))}
                        </div>
                        <p>
                            {t(
                                "Statusänderungen widerrufen gegebenenfalls Sitzungen. Backendregeln schützen privilegierte Konten und den letzten Administrator. MFA-Wiederherstellung erteilt nur den vorgesehenen Auftrag; sie zeigt keine fremden Geheimnisse.",
                            )}
                        </p>
                    </Card>
                    {editRoles && (
                        <UserRoleEditor
                            user={r}
                            onClose={() => setEditRoles(false)}
                            onSaved={() => {
                                setEditRoles(false);
                                setNotice(t("Benutzeränderung bestätigt."));
                                result.reload();
                            }}
                        />
                    )}
                    {operation && (
                        <EditForm
                            key={operation.title}
                            operation={operation}
                            onCancel={() => setOperation(null)}
                            onReload={() => {
                                setOperation(null);
                                result.reload();
                            }}
                            onDone={() => {
                                setOperation(null);
                                setNotice(t("Benutzeränderung bestätigt."));
                                result.reload();
                            }}
                        />
                    )}
                </>
            )}
        </>
    );
}
export function Roles() {
    useLocale();
    const result = useData(base + "roles", rolesSchema);
    const catalog = useData(base + "permissions", rows);
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [notice, setNotice] = useState("");
    const fields: Field[] = [
        { key: "name", label: t("Rollenname"), required: true, max: 128 },
        {
            key: "description",
            label: t("Rollenbeschreibung"),
            type: "textarea",
            max: 512,
        },
        {
            key: "permissions",
            label: t("Delegierbare Berechtigungen"),
            type: "multi",
            options: catalog.data
                ?.filter((p) => p.delegable === true)
                .map((p) => ({
                    id: text(p, "code"),
                    name: text(p, "description"),
                })),
        },
    ];
    return (
        <>
            <h1>{t("Rollenverwaltung")}</h1>
            <p>
                {t(
                    "Systemrollen sind unveränderlich. Benutzerverwaltung gewährt keinen allgemeinen Finding-Zugriff. Neue benutzerdefinierte Rollen können nur die freigegebenen delegierbaren Rechte enthalten.",
                )}
            </p>
            {notice && <p role="status">{translateMessage(notice)}</p>}
            <Allowed permission="role:create">
                <button
                    disabled={!catalog.data}
                    onClick={() =>
                        setOperation({
                            title: t("Benutzerdefinierte Rolle erstellen"),
                            path: base + "roles",
                            method: "POST",
                            fields: [
                                {
                                    key: "code",
                                    label: t("Rollencode"),
                                    required: true,
                                    min: 3,
                                    max: 64,
                                },
                                ...fields,
                            ],
                            initial: { permissions: [], description: "" },
                            validate: (v) =>
                                /^[a-z][a-z0-9_]{2,63}$/.test(String(v.code))
                                    ? null
                                    : t(
                                          "Rollencode: Kleinbuchstaben, Ziffern und Unterstriche verwenden.",
                                      ),
                        })
                    }
                >
                    {t("Rolle erstellen")}
                </button>
            </Allowed>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                result.data.map((r) => (
                    <Card key={r.id} title={r.name}>
                        <Facts values={r} />
                        {!r.is_system && (
                            <div className="actions">
                                <Allowed permission="role:update">
                                    <button
                                        onClick={() =>
                                            setOperation({
                                                title: t(
                                                    "Rolle {0} bearbeiten",
                                                    [r.name],
                                                ),
                                                path: base + "roles/" + r.id,
                                                method: "PATCH",
                                                critical: true,
                                                fields: [...fields, reason],
                                                initial: r,
                                                payload: (v) => ({
                                                    name: v.name,
                                                    description:
                                                        v.description ?? "",
                                                    permissions: v.permissions,
                                                    reason: v.reason,
                                                    version: r.version,
                                                }),
                                            })
                                        }
                                    >
                                        {t("Rolle bearbeiten")}
                                    </button>
                                </Allowed>
                                <Allowed permission="role:delete">
                                    <button
                                        onClick={() =>
                                            setOperation({
                                                title: t("Rolle {0} löschen", [
                                                    r.name,
                                                ]),
                                                path: base + "roles/" + r.id,
                                                method: "DELETE",
                                                critical: true,
                                                fields: [reason],
                                                payload: (v) => ({
                                                    ...v,
                                                    version: r.version,
                                                }),
                                            })
                                        }
                                    >
                                        {t("Rolle löschen")}
                                    </button>
                                </Allowed>
                            </div>
                        )}
                    </Card>
                ))
            )}
            {operation && (
                <EditForm
                    key={operation.title}
                    operation={operation}
                    onCancel={() => setOperation(null)}
                    onReload={() => {
                        setOperation(null);
                        result.reload();
                    }}
                    onDone={() => {
                        setOperation(null);
                        setNotice(t("Rollenversion bestätigt."));
                        result.reload();
                    }}
                />
            )}
        </>
    );
}
export function Access() {
    useLocale();
    const { id = "" } = useParams();
    const result = useData(base + "server-access/" + id, row);
    const server = useData("/api/v1/dashboard/servers/" + id, row);
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [grants, setGrants] = useState<Record<string, string[]> | null>(null);
    const [user, setUser] = useState("");
    const users = useData(base + "users?limit=100", listing);
    const [notice, setNotice] = useState("");
    const current =
        grants ??
        Object.fromEntries(
            ((result.data?.grants as Row[] | undefined) ?? []).map((g) => [
                String(g.user_id),
                [
                    ["view", "can_read"],
                    ["inventory_upload", "can_upload"],
                    ["findings_read", "findings_read"],
                    ["findings_manage", "findings_manage"],
                ]
                    .filter(([, column]) => g[column] === true)
                    .map(([right]) => right),
            ]),
        );
    return (
        <>
            <h1>
                {t("Server-ACL:")}{" "}
                {server.data ? text(server.data, "display_name") : id}
            </h1>
            {!operation && (
                <DraftGuard
                    dirty={grants !== null}
                    onDiscard={() => setGrants(null)}
                />
            )}
            <p>
                {t(
                    "Rechte sind explizit pro Benutzer und Server. Gruppenmitgliedschaften vergeben keine Rechte.",
                )}
            </p>
            {notice && <p role="status">{translateMessage(notice)}</p>}
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <Card title={t("Vollständige ACL prüfen")}>
                    <Inputs
                        fields={[
                            {
                                key: "user",
                                label: t("Benutzer hinzufügen"),
                                type: "picker",
                                source: base + "users",
                            },
                        ]}
                        values={{ user }}
                        set={(_, v) => setUser(String(v ?? ""))}
                    />
                    <button
                        disabled={!user || Object.hasOwn(current, user)}
                        onClick={() => {
                            setGrants({ ...current, [user]: [] });
                            setUser("");
                        }}
                    >
                        {t("Benutzer zur Bearbeitung hinzufügen")}
                    </button>
                    {Object.entries(current).map(([uid, rights]) => (
                        <fieldset key={uid} disabled={!!operation}>
                            <legend>
                                {(users.data?.items.find((u) => u.id === uid)
                                    ?.display_name as string) ?? uid}
                            </legend>
                            {[
                                "view",
                                "inventory_upload",
                                "findings_read",
                                "findings_manage",
                            ].map((right) => (
                                <label className="check" key={right}>
                                    <input
                                        type="checkbox"
                                        checked={rights.includes(right)}
                                        onChange={(e) =>
                                            setGrants({
                                                ...current,
                                                [uid]: e.target.checked
                                                    ? [...rights, right]
                                                    : rights.filter(
                                                          (v) => v !== right,
                                                      ),
                                            })
                                        }
                                    />
                                    {
                                        {
                                            view: t("Server lesen"),
                                            inventory_upload:
                                                t("Inventar hochladen"),
                                            findings_read: t("Findings lesen"),
                                            findings_manage:
                                                t("Findings verwalten"),
                                        }[right]
                                    }
                                </label>
                            ))}
                            <button
                                onClick={() => {
                                    const next = { ...current };
                                    delete next[uid];
                                    setGrants(next);
                                }}
                            >
                                {t("ACL-Eintrag entfernen")}
                            </button>
                        </fieldset>
                    ))}
                    {grants && (
                        <button
                            onClick={() =>
                                setOperation({
                                    title: t("ACL für {0} ersetzen", [
                                        server.data
                                            ? text(server.data, "display_name")
                                            : id,
                                    ]),
                                    path: base + "server-access/" + id,
                                    method: "PUT",
                                    critical: true,
                                    fields: [reason],
                                    validate: () =>
                                        Object.values(current).some(
                                            (rights) =>
                                                rights.length === 0 ||
                                                !rights.includes("view") ||
                                                (rights.includes(
                                                    "findings_manage",
                                                ) &&
                                                    !rights.includes(
                                                        "findings_read",
                                                    )),
                                        )
                                            ? t(
                                                  "Jeder Eintrag benötigt Server-Leserecht; Findings verwalten benötigt Findings lesen. Leere Einträge entfernen.",
                                              )
                                            : null,
                                    payload: (v) => ({
                                        version: version(result.data!),
                                        reason: v.reason,
                                        grants: Object.entries(current).map(
                                            ([user_id, rights]) => ({
                                                user_id,
                                                rights,
                                            }),
                                        ),
                                    }),
                                })
                            }
                        >
                            {t("ACL-Änderung prüfen")}
                        </button>
                    )}
                </Card>
            )}
            {operation && (
                <EditForm
                    operation={{ ...operation, dirty: true }}
                    onCancel={() => {
                        setOperation(null);
                        setGrants(null);
                    }}
                    onReload={() => {
                        setOperation(null);
                        setGrants(null);
                        result.reload();
                    }}
                    onDone={() => {
                        setOperation(null);
                        setGrants(null);
                        setNotice(t("Neue ACL-Version bestätigt."));
                        result.reload();
                    }}
                />
            )}
        </>
    );
}
