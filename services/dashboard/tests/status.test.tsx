import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import * as ui from "../src/ui";
import { ObservationChart, StatusBadge, StatusOverview } from "../src/status";
vi.mock("../src/auth", () => ({
    useAuth: () => ({
        identity: {
            permissions: [
                "deployment:status:read",
                "deployment:diagnostics:read",
            ],
        },
    }),
}));
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
describe("Status truthfulness and accessible measurements", () => {
    for (const [state, label] of Object.entries({
        healthy: "Gesund",
        degraded: "Eingeschränkt",
        unavailable: "Nicht verfügbar",
        unknown: "Unbekannt",
        starting: "Startphase",
        maintenance: "Wartung",
    })) {
        it("labels " + state + " with text instead of color alone", () => {
            render(<StatusBadge value={state} />);
            expect(screen.getByText(new RegExp(label))).toBeInTheDocument();
        });
    }
    it("does not retain a green state when the aggregate API fails", () => {
        vi.spyOn(ui, "useData").mockReturnValue({
            data: null,
            error: new Error("API unavailable"),
            reload: vi.fn(),
        });
        render(
            <MemoryRouter>
                <StatusOverview />
            </MemoryRouter>,
        );
        expect(screen.getByRole("alert")).toHaveTextContent(
            "Plattformzustand ist unbekannt",
        );
        expect(screen.queryByText("Gesund")).not.toBeInTheDocument();
    });
    it("keeps empty history unknown rather than generating chart points", () => {
        render(<ObservationChart samples={[]} />);
        expect(
            screen.getByText("Keine Rohmessungen verfügbar."),
        ).toBeInTheDocument();
        expect(screen.queryByRole("img")).not.toBeInTheDocument();
    });
    it("offers a table with the actual values and no interpolated healthy intervals", () => {
        render(
            <ObservationChart
                samples={[
                    {
                        checked_at: "2026-11-10T04:00:00Z",
                        result: "unknown",
                        duration_ms: 20,
                        metrics: { pending: 5 },
                    },
                    {
                        checked_at: "2026-11-10T05:00:00Z",
                        result: "unavailable",
                        duration_ms: 30,
                        metrics: { pending: 12 },
                    },
                ]}
            />,
        );
        expect(screen.getByRole("table")).toHaveTextContent("Unbekannt");
        expect(screen.getByRole("table")).toHaveTextContent("Nicht verfügbar");
        expect(screen.getByRole("table")).toHaveTextContent("12");
        expect(document.querySelectorAll("svg rect")).toHaveLength(2);
    });
});
