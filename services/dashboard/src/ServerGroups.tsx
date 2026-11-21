import { useState } from "react";
import { z } from "zod";
import { Link } from "react-router-dom";
import { t, useLocale } from "./i18n";
import { useData, State, Card } from "./ui";
import { EditForm, type Mutation } from "./admin/Form";

export const personalGroupsSchema = z.object({
    version: z.number().int().nonnegative(),
    items: z.array(
        z.object({
            id: z.string(),
            name: z.string(),
            description: z.string().nullable(),
            server_ids: z.array(z.string()),
        }),
    ),
});
const endpoint = "/api/v1/dashboard/groups";
export function useServerGroups() {
    return useData(endpoint, personalGroupsSchema, {
        changeEvent: "server-groups-changed",
    });
}
export function ServerGroups({ embedded = false }: { embedded?: boolean }) {
    useLocale();
    const result = useServerGroups();
    const [operation, setOperation] = useState<Mutation | null>(null);
    const fields = [
        { key: "name", label: t("Name"), required: true, max: 128 },
        {
            key: "description",
            label: t("Beschreibung"),
            type: "textarea" as const,
            max: 2000,
        },
    ];
    return (
        <>
            {!embedded && <h1>{t("Gruppen")}</h1>}
            <Card title={t("Gruppen")}>
                <p>
                    {t(
                        "Gruppen sind persönlich. Ein Server kann mehreren Gruppen angehören. Gruppenzuordnungen ändern keine Zugriffsrechte.",
                    )}
                </p>
                <button
                    disabled={!result.data}
                    onClick={() =>
                        setOperation({
                            title: t("Gruppe anlegen"),
                            path: endpoint,
                            method: "POST",
                            stepUp: false,
                            fields,
                            payload: (v) => ({
                                ...v,
                                version: result.data!.version,
                            }),
                        })
                    }
                >
                    {t("Gruppe anlegen")}
                </button>
                {!result.data ? (
                    <State error={result.error} reload={result.reload} />
                ) : result.data.items.length ? (
                    <ul className="server-group-list">
                        {result.data.items.map((g) => (
                            <li key={g.id}>
                                <div>
                                    <Link to={`/servers?group_id=${g.id}`}>
                                        {g.name}
                                    </Link>
                                    <small>{g.description}</small>
                                    <span>
                                        {t("{0} Server", [g.server_ids.length])}
                                    </span>
                                </div>
                                <div className="actions">
                                    <button
                                        aria-label={t("Gruppe {0} bearbeiten", [
                                            g.name,
                                        ])}
                                        onClick={() =>
                                            setOperation({
                                                title: t(
                                                    "Gruppe {0} bearbeiten",
                                                    [g.name],
                                                ),
                                                path: endpoint + "/" + g.id,
                                                method: "PUT",
                                                stepUp: false,
                                                fields,
                                                initial: g,
                                                payload: (v) => ({
                                                    name: v.name,
                                                    description: v.description,
                                                    version:
                                                        result.data!.version,
                                                }),
                                            })
                                        }
                                    >
                                        {t("Bearbeiten")}
                                    </button>
                                    <button
                                        aria-label={t("Gruppe {0} löschen", [
                                            g.name,
                                        ])}
                                        onClick={() =>
                                            setOperation({
                                                title: t("Gruppe {0} löschen", [
                                                    g.name,
                                                ]),
                                                path: endpoint + "/" + g.id,
                                                method: "DELETE",
                                                stepUp: false,
                                                critical: true,
                                                fields: [],
                                                payload: () => ({
                                                    version:
                                                        result.data!.version,
                                                }),
                                            })
                                        }
                                    >
                                        {t("Löschen")}
                                    </button>
                                </div>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p>{t("Noch keine Gruppen vorhanden.")}</p>
                )}
            </Card>
            {operation && (
                <EditForm
                    key={operation.title}
                    operation={operation}
                    onCancel={() => setOperation(null)}
                    onDone={() => {
                        setOperation(null);
                        result.reload();
                        window.dispatchEvent(
                            new Event("server-groups-changed"),
                        );
                    }}
                    onReload={() => {
                        setOperation(null);
                        result.reload();
                    }}
                />
            )}
        </>
    );
}
export function AssignServerGroups({
    server,
    name,
    onSaved,
}: {
    server: string;
    name: string;
    onSaved: () => void;
}) {
    useLocale();
    const [open, setOpen] = useState(false);
    return (
        <>
            <button onClick={() => setOpen(true)}>
                {t("Gruppen zuordnen")}
            </button>
            {open && (
                <GroupAssignment
                    server={server}
                    name={name}
                    onClose={() => setOpen(false)}
                    onSaved={() => {
                        setOpen(false);
                        onSaved();
                        window.dispatchEvent(
                            new Event("server-groups-changed"),
                        );
                    }}
                />
            )}
        </>
    );
}
function GroupAssignment({
    server,
    name,
    onClose,
    onSaved,
}: {
    server: string;
    name: string;
    onClose: () => void;
    onSaved: () => void;
}) {
    useLocale();
    const result = useServerGroups();
    if (!result.data)
        return (
            <Card title={t("Gruppen für {0} zuordnen", [name])}>
                <State error={result.error} reload={result.reload} />
                <button onClick={onClose}>{t("Abbrechen")}</button>
            </Card>
        );
    return (
        <EditForm
            operation={{
                title: t("Gruppen für {0} zuordnen", [name]),
                path: `/api/v1/dashboard/servers/${server}/groups`,
                method: "PUT",
                stepUp: false,
                fields: [
                    {
                        key: "group_ids",
                        label: t("Gruppen"),
                        type: "multi",
                        options: result.data.items.map((g) => ({
                            id: g.id,
                            name: g.name,
                        })),
                    },
                ],
                initial: {
                    group_ids: result.data.items
                        .filter((g) => g.server_ids.includes(server))
                        .map((g) => g.id),
                },
                payload: (v) => ({
                    group_ids: v.group_ids,
                    version: result.data!.version,
                }),
            }}
            onCancel={onClose}
            onDone={onSaved}
            onReload={result.reload}
        />
    );
}
