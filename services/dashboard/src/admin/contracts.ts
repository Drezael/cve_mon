import type { components } from "../generated/administration";
import { z } from "zod";
export const row = z.object({}).catchall(z.unknown());
export type Row = z.infer<typeof row>;
export const rows = z.array(row);
export const listing = z.object({
    items: rows,
    total: z.number(),
    limit: z.number(),
    offset: z.number(),
});
export const itemList = z.object({ items: rows });
export const order = z.object({
    items: rows,
    version: z.number(),
    total: z.number(),
});
export const rolesSchema = z.array(
    z.object({
        id: z.string(),
        code: z.string(),
        name: z.string(),
        description: z
            .string()
            .nullish()
            .transform((value) => value ?? ""),
        is_system: z.boolean(),
        version: z.number(),
        permissions: z.array(z.string()),
    }),
);
export const text = (r: Row, key: string) =>
    typeof r[key] === "string" ? String(r[key]) : "";
export const version = (r: Row) =>
    typeof r.version === "number" ? r.version : 0;
export const selected = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((i): i is string => typeof i === "string") : [];
export const priorities = ["unrated", "low", "medium", "high", "critical"];
export const events = [
    "created",
    "confirmed_affected",
    "potentially_affected",
    "reopened",
    "priority_changed",
    "resolved",
    "closed",
    "assigned",
    "deadline_approaching",
    "overdue",
    "exception_approved",
    "exception_approaching",
    "exception_expired",
    "exception_revoked",
    "status_unavailable",
    "status_recovered",
];

export const serverCreateSchema: z.ZodType<
    components["schemas"]["ServerCreate"]
> = z
    .object({
        request_id: z.string().uuid(),
        display_name: z.string().min(1).max(128),
        description: z.string().max(2000).nullable().optional(),
        environment: z.string().min(1).max(64).nullable().optional(),
        criticality: z
            .enum(["low", "medium", "high", "critical"])
            .default("medium"),
        exposure: z
            .enum(["unknown", "internal", "restricted", "internet_exposed"])
            .default("unknown"),
    })
    .strict();
export const userCreateSchema: z.ZodType<components["schemas"]["UserCreate"]> =
    z
        .object({
            username: z.string().min(1).max(128),
            display_name: z.string().min(1).max(128),
            email: z.string().email().max(254),
        })
        .strict();
