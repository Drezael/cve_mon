import { beforeEach, afterEach, it, expect, vi } from "vitest";
import {
    render,
    screen,
    fireEvent,
    waitFor,
    cleanup,
} from "@testing-library/react";
import { MfaSettings } from "../src/admin/MfaSettings";
import * as auth from "../src/auth";
import * as client from "../src/api";

const refresh = vi.fn();
const setSecret = vi.fn();
const setCodes = vi.fn();
function context(secret: string | null = null) {
    vi.spyOn(auth, "useAuth").mockReturnValue({
        identity: null,
        checking: false,
        enrollmentSecret: secret,
        setEnrollmentSecret: setSecret,
        recoveryCodes: [],
        setRecoveryCodes: setCodes,
        refresh,
        logoutError: "",
        logout: vi.fn(),
    });
}
beforeEach(() => {
    vi.clearAllMocks();
});
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
it("MFA starts as an optional disabled account preference", () => {
    context();
    render(<MfaSettings enabled={false} reload={vi.fn()} />);
    expect(screen.getByText(/MFA ist deaktiviert/)).toBeInTheDocument();
    expect(
        screen.getByRole("button", { name: "MFA einrichten" }),
    ).toBeInTheDocument();
    expect(
        screen.queryByRole("button", { name: "MFA deaktivieren" }),
    ).toBeNull();
});
it("pending enrollment requires the code and exposes recovery codes only on success", async () => {
    context("SYNTHETICENROLLMENT");
    const call = vi.spyOn(client, "api").mockResolvedValue({
        state: "authenticated",
        recovery_codes: ["synthetic-recovery-code"],
    });
    const reload = vi.fn();
    render(<MfaSettings enabled={false} reload={reload} />);
    fireEvent.change(screen.getByLabelText("Sechsstelliger Bestätigungscode"), {
        target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "MFA aktivieren" }));
    await waitFor(() =>
        expect(setCodes).toHaveBeenCalledWith(["synthetic-recovery-code"]),
    );
    expect(call).toHaveBeenCalledWith(
        "/api/v1/auth/mfa/enroll/confirm",
        expect.anything(),
        { method: "POST", body: { code: "123456" } },
    );
    expect(setSecret).toHaveBeenCalledWith(null);
    expect(reload).toHaveBeenCalled();
});
it("cancel leaves the active factor alone", async () => {
    context("SYNTHETICENROLLMENT");
    const call = vi.spyOn(client, "api").mockResolvedValue(null);
    render(<MfaSettings enabled={true} reload={vi.fn()} />);
    fireEvent.click(
        screen.getByRole("button", { name: "Einrichtung abbrechen" }),
    );
    await waitFor(() => expect(setSecret).toHaveBeenCalledWith(null));
    expect(call).toHaveBeenCalledTimes(1);
    expect(call).toHaveBeenCalledWith(
        "/api/v1/auth/mfa/enroll/cancel",
        expect.anything(),
        { method: "POST", body: {} },
    );
});
it("failed confirmation keeps the pending setup available", async () => {
    context("SYNTHETICENROLLMENT");
    vi.spyOn(client, "api").mockRejectedValue(new Error("Ungültiger Code"));
    render(<MfaSettings enabled={false} reload={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Sechsstelliger Bestätigungscode"), {
        target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "MFA aktivieren" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
        "Ungültiger Code",
    );
    expect(setSecret).not.toHaveBeenCalled();
    expect(setCodes).not.toHaveBeenCalled();
});
