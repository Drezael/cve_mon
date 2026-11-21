import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import Threat, { threatLevel } from "../src/Threat";

describe("CVE threat indicator", () => {
    it("shows a readable severity and actual CVSS score", () => {
        render(
            <Threat
                finding={{
                    current_priority: "unrated",
                    cvss: { base_score: 8.1 },
                }}
            />,
        );
        expect(screen.getByText("Hoch")).toBeVisible();
        expect(screen.getByText("CVSS 8.1/10")).toBeVisible();
    });
    it("marks current KEV exploitation critical without inventing a CVSS score", () => {
        const f = {
            current_priority: "low",
            kev_status: "present",
            kev_is_current: true,
        };
        expect(threatLevel(f).level).toBe("critical");
        expect(Number.isNaN(threatLevel(f).score)).toBe(true);
    });
    it("does not escalate based on stale EPSS or stale KEV", () => {
        expect(
            threatLevel({
                current_priority: "low",
                epss: { score: 0.95, is_stale: true },
                kev_status: "present",
                kev_is_current: false,
            }).level,
        ).toBe("low");
        expect(
            threatLevel({
                current_priority: "low",
                epss: { score: 0.5, is_stale: false },
            }).level,
        ).toBe("high");
    });
});
