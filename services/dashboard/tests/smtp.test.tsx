import { afterEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import SMTPSettings from "../src/admin/SMTP";
import * as ui from "../src/ui";
import * as client from "../src/api";
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
const settings = {
    enabled: true,
    host: "smtp.example.org",
    port: 587,
    sender: "security@example.org",
    recipients: ["user@example.org"],
    id: crypto.randomUUID(),
    version: 4,
    state: "applied",
    username: "smtp-account",
    password_configured: true,
    created_at: null,
    finished_at: null,
    error_code: null,
    execution_id: "42",
};
it("shows safe SMTP settings and keeps the saved password blank", () => {
    vi.spyOn(ui, "useData").mockReturnValue({
        data: settings,
        error: null,
        reload: vi.fn(),
    });
    render(<SMTPSettings />);
    expect(screen.getByLabelText("SMTP-Server")).toHaveValue(
        "smtp.example.org",
    );
    expect(screen.getByLabelText("SMTP-Passwort")).toHaveValue("");
    expect(screen.getByText(/Passwort ist gespeichert/)).toBeInTheDocument();
});
it("queues a versioned configuration and preserves a blank password", async () => {
    vi.spyOn(ui, "useData").mockReturnValue({
        data: settings,
        error: null,
        reload: vi.fn(),
    });
    const save = vi
        .spyOn(client, "api")
        .mockResolvedValue({ ...settings, state: "waiting" });
    render(<SMTPSettings />);
    fireEvent.click(
        screen.getByRole("button", { name: "Speichern und über n8n anwenden" }),
    );
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    const options = save.mock.calls[0][2];
    expect(options?.method).toBe("PUT");
    expect(options?.idempotencyKey).toMatch(/^[a-f0-9-]{36}$/);
    expect(options?.body).toMatchObject({
        version: 4,
        password: null,
        host: "smtp.example.org",
    });
    await screen.findByText(/in die n8n-Queue eingereiht/);
});
it("prevents another configuration while n8n is applying it", () => {
    vi.spyOn(ui, "useData").mockReturnValue({
        data: { ...settings, state: "waiting" },
        error: null,
        reload: vi.fn(),
    });
    render(<SMTPSettings />);
    expect(
        screen.getByRole("button", { name: "Wartet auf Anwendung über n8n" }),
    ).toBeDisabled();
    expect(screen.getByLabelText("SMTP-Server")).toBeDisabled();
});

it("uses the central server without exposing its credentials and saves multiple personal recipients", async () => {
    vi.spyOn(ui, "useData").mockReturnValue({
        data: {
            ...settings,
            enabled: false,
            mode: "system",
            system_available: true,
            host: "",
            username: "",
        },
        error: null,
        reload: vi.fn(),
    });
    const save = vi.spyOn(client, "api").mockResolvedValue({
        ...settings,
        state: "waiting",
        mode: "system",
        system_available: true,
    });
    render(<SMTPSettings personal />);
    expect(
        screen.getByRole("heading", { name: "Meine Mail-Einstellungen" }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("SMTP-Passwort")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Meine Empfängeradressen"), {
        target: { value: "one@example.org\ntwo@example.org;three@example.org" },
    });
    fireEvent.click(
        screen.getByRole("button", { name: "Speichern und über n8n anwenden" }),
    );
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(save.mock.calls[0][0]).toBe("/api/v1/dashboard/notifications/mail");
    expect(save.mock.calls[0][2]?.body).toMatchObject({
        mode: "system",
        enabled: false,
        recipients: ["one@example.org", "two@example.org", "three@example.org"],
    });
});
it("allows a user to select their own SMTP server", () => {
    vi.spyOn(ui, "useData").mockReturnValue({
        data: { ...settings, mode: "system", system_available: false },
        error: null,
        reload: vi.fn(),
    });
    render(<SMTPSettings personal />);
    expect(screen.queryByLabelText("SMTP-Passwort")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("SMTP-Auswahl"), {
        target: { value: "custom" },
    });
    expect(screen.getByLabelText("SMTP-Server")).toHaveValue(
        "smtp.example.org",
    );
    expect(screen.getByLabelText("SMTP-Passwort")).toHaveValue("");
});

it("queues a test of saved settings without resending credentials", async () => {
    const reload = vi.fn();
    vi.spyOn(ui, "useData").mockImplementation((path) => ({
        data: path.endsWith("/test")
            ? { id: null, state: "unconfigured", error_code: null }
            : settings,
        error: null,
        reload,
    }));
    const send = vi.spyOn(client, "api").mockResolvedValue({
        id: crypto.randomUUID(),
        state: "waiting",
        error_code: null,
    });
    render(<SMTPSettings />);
    fireEvent.change(screen.getByLabelText("Testempfänger (optional)"), {
        target: { value: "test@example.org" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Testmail senden" }));
    await waitFor(() => expect(send).toHaveBeenCalledTimes(1));
    expect(send.mock.calls[0][0]).toBe(
        "/api/v1/dashboard/administration/smtp/test",
    );
    expect(send.mock.calls[0][2]).toMatchObject({
        method: "POST",
        body: { recipient: "test@example.org" },
    });
    expect(send.mock.calls[0][2]?.idempotencyKey).toMatch(/^[a-f0-9-]{36}$/);
    expect(reload).toHaveBeenCalled();
});

it("shows the safe test error and prevents duplicate pending tests", () => {
    vi.spyOn(ui, "useData").mockImplementation((path) => ({
        data: path.endsWith("/test")
            ? {
                  id: crypto.randomUUID(),
                  state: "waiting",
                  error_code: "SMTP_AUTHENTICATION_FAILED",
              }
            : settings,
        error: null,
        reload: vi.fn(),
    }));
    render(<SMTPSettings personal />);
    expect(
        screen.getByRole("button", { name: "Testmail wird versendet …" }),
    ).toBeDisabled();
    expect(screen.getByText(/Anmeldung fehlgeschlagen/)).toBeInTheDocument();
});
