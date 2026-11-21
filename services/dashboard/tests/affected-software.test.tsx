import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import AffectedSoftware from "../src/AffectedSoftware";

afterEach(cleanup);
const base = {
    component_id: "package-1",
    name: "pac-resolver",
    version: "4.2.0",
    location: "host" as const,
    container_id: null,
    container_name: null,
    origin: null,
    target: null,
    status: "potentially_affected",
};
it("shows host package name, version and affected status", () => {
    render(<AffectedSoftware items={[base]} />);
    expect(screen.getByText("pac-resolver")).toBeVisible();
    expect(screen.getByText("4.2.0")).toBeVisible();
    expect(screen.getByText("Host")).toBeVisible();
    expect(screen.getByText("Betroffen")).toBeVisible();
});
it("keeps host and named container separate for the same package", () => {
    render(
        <AffectedSoftware
            items={[
                base,
                {
                    ...base,
                    component_id: "container-package",
                    location: "container",
                    container_id: "c1",
                    container_name: "web",
                    origin: "mount",
                    target: "/app",
                },
            ]}
        />,
    );
    expect(screen.getAllByText("pac-resolver")).toHaveLength(2);
    expect(screen.getByText("Host")).toBeVisible();
    expect(screen.getByText("Container: web")).toBeVisible();
    expect(screen.getByText(/Eingebundene Anwendung/)).toBeVisible();
});
it("does not infer software or host placement when evidence is missing", () => {
    render(
        <AffectedSoftware
            items={[
                { ...base, name: null, version: null, location: "unknown" },
            ]}
        />,
    );
    expect(
        screen.getByText("Software nicht eindeutig ermittelt"),
    ).toBeVisible();
    expect(screen.getByText("Bereich nicht eindeutig ermittelt")).toBeVisible();
    expect(screen.queryByText("Host")).not.toBeInTheDocument();
});
it("keeps a negative component assessment visible in compact finding rows", () => {
    render(
        <AffectedSoftware
            compact
            items={[{ ...base, status: "not_affected" }]}
        />,
    );
    expect(screen.getByText("Nicht betroffen")).toBeVisible();
});
