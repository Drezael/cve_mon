import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { safePath, safeLink, percent } from "../src/format";
import { Badge, FindingRows, Distribution, Facts } from "../src/ui";
import { api, clearPrivate, ApiError } from "../src/api";
import { z } from "zod";
afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    clearPrivate();
});
describe("Untrusted values", () => {
    it("only allows known internal return paths", () => {
        for (const path of [
            "https://evil.test",
            "//evil.test",
            "/api/v1/auth",
            "/dashboard/../../evil",
            "/findings?token=<script>",
        ])
            expect(safePath(path)).toBe("/dashboard");
        expect(safePath("/servers")).toBe("/servers");
    });
    it("rejects executable and credential URLs", () => {
        expect(safeLink("javascript:alert(1)")).toBeNull();
        expect(safeLink("https://user:secret@example.test")).toBeNull(); // pragma: allowlist secret -- synthetic rejected URL
        expect(safeLink("https://nvd.nist.gov")).toBe("https://nvd.nist.gov/");
    });
    it("does not treat missing EPSS as zero", () => {
        expect(percent(null)).toBe("Unbekannt");
        expect(percent("")).toBe("Unbekannt");
        expect(percent(0)).toBe("0 %");
        expect(percent(0.125)).toBe("12,5 %");
        expect(percent(3)).toBe("Unbekannt");
    });
    it("renders markup as text", () => {
        render(<Badge value={"<img src=x onerror=alert(1)>"} />);
        expect(document.querySelector("img")).toBeNull();
        expect(
            screen.getByText("<img src=x onerror=alert(1)>"),
        ).toBeInTheDocument();
    });
    it("provides accessible chart values and empty findings", () => {
        render(
            <MemoryRouter>
                <Distribution
                    title="Priorität"
                    values={{ critical: 3, high: 7 }}
                />
                <FindingRows items={[]} />
            </MemoryRouter>,
        );
        expect(
            screen.getByRole("table", { name: "Priorität" }),
        ).toHaveTextContent("Kritisch3Hoch7");
        expect(
            screen.getByText("Keine Findings für diese Auswahl."),
        ).toBeInTheDocument();
    });
});
describe("Contract risk values", () => {
    it("renders the actual versioned CVSS and EPSS contract", () => {
        render(
            <MemoryRouter>
                <FindingRows
                    items={[
                        {
                            id: "finding",
                            server_id: "server",
                            cve_id: "CVE-2026-1234",
                            current_priority: "high",
                            latest_matching_status: "unknown",
                            lifecycle_status: "open",
                            due_at: null,
                            is_overdue: false,
                            cvss: {
                                cvss_version: "3.1",
                                base_score: "8.1",
                                validation_status: "valid",
                            },
                            epss: {
                                score: "0.125",
                                score_date: "2026-11-09",
                                is_stale: true,
                            },
                            kev_status: "present",
                            kev_is_current: true,
                        },
                    ]}
                />
            </MemoryRouter>,
        );
        expect(screen.getByText(/CVSS 3.1: 8.1/)).toBeInTheDocument();
        expect(screen.getByText(/EPSS: 12,5/)).toBeInTheDocument();
        expect(screen.getByText(/2026-11-09/)).toBeInTheDocument();
    });
    it("escapes nested evidence", () => {
        render(
            <Facts
                values={{
                    decision: { name: "<script>alert(1)</script>" },
                    source: "javascript:alert(1)",
                }}
            />,
        );
        expect(document.querySelector("script")).toBeNull();
        expect(document.querySelector("a")).toBeNull();
    });
});
describe("Request boundary", () => {
    it("keeps 503 distinct from an empty result", async () => {
        vi.stubGlobal(
            "fetch",
            vi.fn().mockResolvedValue(new Response("{}", { status: 503 })),
        );
        await expect(
            api("/api/v1/dashboard/overview", z.object({ total: z.number() })),
        ).rejects.toMatchObject({ status: 503 });
    });
    it("rejects invalid response contracts", async () => {
        vi.stubGlobal(
            "fetch",
            vi.fn().mockResolvedValue(new Response('{"total":"zero"}')),
        );
        await expect(
            api("/api/v1/dashboard/overview", z.object({ total: z.number() })),
        ).rejects.toMatchObject({ status: 502 });
    });
    it("drops responses after logout generation changes", async () => {
        let done: (value: Response) => void = () => {};
        vi.stubGlobal(
            "fetch",
            vi.fn(
                () =>
                    new Promise<Response>((resolve) => {
                        done = resolve;
                    }),
            ),
        );
        const request = api(
            "/api/v1/dashboard/overview",
            z.object({ total: z.number() }),
        );
        clearPrivate();
        done(new Response('{"total":9}'));
        await expect(request).rejects.toMatchObject({ name: "AbortError" });
    });
    it("denies non-API paths", async () => {
        await expect(
            api("https://example.test", z.unknown()),
        ).rejects.toBeInstanceOf(ApiError);
    });
});
