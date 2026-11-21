import { t } from "./../i18n";
import type { Row } from "./contracts";

// Display a technical actor without changing the event's human user reference.
export function auditFacts(record: Row): Row {
    const { actor_service, actor_username, ...values } = record;
    return {
        ...values,
        actor_user_id:
            record.actor_user_id !== null && record.actor_user_id !== undefined
                ? typeof actor_username === "string" &&
                  actor_username.length > 0
                    ? actor_username
                    : t("Benutzername nicht verfügbar")
                : typeof actor_service === "string" && actor_service.length > 0
                  ? t("Service: {0}", [actor_service])
                  : t("Service nicht protokolliert"),
    };
}
