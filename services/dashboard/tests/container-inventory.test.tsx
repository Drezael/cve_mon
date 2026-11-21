import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import * as client from "../src/api";
import ContainerInventory from "../src/ContainerInventory";

afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
it("shows missing software evidence without suggesting a clean scan", async () => {
    vi.spyOn(client, "api").mockResolvedValue({
        items: [
            {
                container_id: "c1",
                name: "web",
                image_id: "sha256:test",
                image_reference: "web:latest",
                state: "running",
                scans: [],
            },
        ],
        total: 1,
    });
    render(<ContainerInventory server="server" />);
    expect(await screen.findByText("Nicht erfasst")).toBeVisible();
});
it("opens the package inventory with its container provenance", async () => {
    vi.spyOn(client, "api").mockImplementation(async (path) =>
        path.includes("container-software")
            ? {
                  items: [
                      {
                          scope: "mount",
                          target: "/opt/application",
                          status: "complete",
                          os: {},
                          package: {
                              name: "pac-resolver",
                              version: "4.2.0",
                              type: "npm",
                          },
                      },
                  ],
                  total: 1,
              }
            : {
                  items: [
                      {
                          container_id: "c1",
                          name: "web",
                          image_id: "sha256:test",
                          image_reference: "web:latest",
                          state: "running",
                          scans: [
                              {
                                  scope: "image",
                                  target: null,
                                  status: "complete",
                                  captured_at: "2026-11-14T12:00:00Z",
                                  error_code: null,
                                  package_count: 1,
                                  scanner_version: "1.57.1",
                              },
                          ],
                      },
                  ],
                  total: 1,
              },
    );
    render(<ContainerInventory server="server" />);
    fireEvent.click(await screen.findByRole("button", { name: "web" }));
    expect(await screen.findByText("pac-resolver")).toBeVisible();
    expect(screen.getByText("4.2.0")).toBeVisible();
    expect(screen.getByText("mount /opt/application")).toBeVisible();
});
