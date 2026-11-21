import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { auditFacts } from "../src/admin/audit";
import { Facts } from "../src/ui";
afterEach(cleanup);
it("shows the service in Benutzer when no user initiated the event", () => {
    const record = {
        actor_user_id: null,
        actor_service: "importer",
        action: "cve.source.completed",
    };
    render(<Facts values={auditFacts(record)} />);
    expect(screen.getByText("Benutzer").nextElementSibling).toHaveTextContent(
        "Service: importer",
    );
    expect(screen.queryByText("Unbekannt")).not.toBeInTheDocument();
    expect(record.actor_user_id).toBeNull();
});
it("shows the username instead of the ID and preserves the original reference", () => {
    const actor = crypto.randomUUID();
    const record = {
        actor_user_id: actor,
        actor_username: "gerald",
        actor_service: "importer",
    };
    render(<Facts values={auditFacts(record)} />);
    expect(screen.getByText("Benutzer").nextElementSibling).toHaveTextContent(
        "gerald",
    );
    expect(screen.queryByText(actor)).not.toBeInTheDocument();
    expect(screen.queryByText("Service: importer")).not.toBeInTheDocument();
    expect(record.actor_user_id).toBe(actor);
});
it("does not fall back to a UUID when a username is missing", () => {
    const actor = crypto.randomUUID();
    expect(auditFacts({ actor_user_id: actor }).actor_user_id).toBe(
        "Benutzername nicht verfügbar",
    );
});
it("does not invent a service when an older backend provided no attribution", () => {
    expect(auditFacts({ actor_user_id: null }).actor_user_id).toBe(
        "Service nicht protokolliert",
    );
});

it.each(["unknown", "open", "healthy"])(
    "does not translate username %s as a status",
    (username) => {
        render(
            <Facts
                values={auditFacts({
                    actor_user_id: crypto.randomUUID(),
                    actor_username: username,
                })}
            />,
        );
        expect(
            screen.getByText("Benutzer").nextElementSibling,
        ).toHaveTextContent(username);
    },
);
