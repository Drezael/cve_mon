import { t, useLocale } from "./i18n";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./auth";
import { EditForm, type Mutation } from "./admin/Form";
import { serverCreateSchema } from "./admin/contracts";
import { serverFields } from "./admin/serverFields";
import Upload from "./admin/Upload";

export function CreateServerButton() {
    useLocale();
    const { identity } = useAuth();
    const navigate = useNavigate();
    if (
        !identity?.permissions.some((permission) =>
            ["server:create", "server:inventory:manage"].includes(permission),
        )
    )
        return null;
    return (
        <button onClick={() => navigate("/servers/new")}>
            {t("Server anlegen")}
        </button>
    );
}

export default function ServerCreation() {
    useLocale();
    const { identity } = useAuth();
    const permissions = identity?.permissions ?? [];
    if (permissions.includes("server:inventory:manage")) {
        return <Upload manualAllowed={permissions.includes("server:create")} />;
    }
    return <ManualServerCreation />;
}

function ManualServerCreation() {
    useLocale();
    const navigate = useNavigate();
    const [operation] = useState<Mutation>(() => {
        const requestId = crypto.randomUUID();
        return {
            title: t("Server anlegen"),
            path: "/api/v1/dashboard/admin/servers",
            method: "POST",
            fields: serverFields,
            initial: { criticality: "medium", exposure: "unknown" },
            idempotent: true,
            validate: (values) =>
                serverCreateSchema.safeParse({
                    ...values,
                    request_id: requestId,
                    description: values.description || null,
                    environment: values.environment || null,
                }).success
                    ? null
                    : t("Bitte die Serverfelder prüfen."),
            payload: (values) => ({
                ...values,
                request_id: requestId,
                description: values.description || null,
                environment: values.environment || null,
            }),
        };
    });
    return (
        <EditForm
            operation={operation}
            onCancel={() => navigate("/servers")}
            onReload={() => navigate("/servers")}
            onDone={(server) => {
                if (server?.id) navigate("/servers", { replace: true });
            }}
        />
    );
}
