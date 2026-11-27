import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import * as ui from "../src/ui";
import { ApiError } from "../src/api";
import FindingTrend from "../src/pages/FindingTrend";

afterEach(()=>{cleanup();vi.restoreAllMocks();});
const data = {items:[{day:"2026-11-25",detected:2,resolved:1,reopened:0,closed:0}]};
it("marks retained trend as stale after a failed refresh",()=>{
    vi.spyOn(ui,"useData").mockReturnValue({data,error:new ApiError(503),updatedAt:"2026-11-25T10:00:00Z",reload:vi.fn()});
    render(<FindingTrend />);
    expect(screen.getByRole("img")).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent("Aktualisierung fehlgeschlagen");
    expect(screen.getByRole("button",{name:"Aktualisieren"})).toBeVisible();
});
it("hides previously loaded trend when access is revoked",()=>{
    vi.spyOn(ui,"useData").mockReturnValue({data,error:new ApiError(403),reload:vi.fn()});
    render(<FindingTrend />);
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.getByRole("alert")).toBeVisible();
});
