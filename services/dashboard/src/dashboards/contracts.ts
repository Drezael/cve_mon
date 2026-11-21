import { z } from "zod";
const common = {
    id: z.string(),
    title: z.string(),
    span: z.number().int().min(1).max(3),
};
const serverFilters = z.object({
    group_id: z.string().nullable().optional(),
    search: z.string().optional(),
    distribution: z.string().nullable().optional(),
});
const findingFilters = z.object({
    server_id: z.string().nullable().optional(),
    group_id: z.string().nullable().optional(),
    priority: z.string().nullable().optional(),
    lifecycle: z.string().nullable().optional(),
    kev: z.boolean().nullable().optional(),
    overdue: z.boolean().nullable().optional(),
});
export const widgetSchema = z.discriminatedUnion("type", [
    z.object({
        ...common,
        type: z.literal("metric"),
        metric: z.enum([
            "active_servers",
            "servers_affected",
            "open_findings",
            "critical",
            "high",
            "overdue",
            "kev",
            "unknown",
        ]),
    }),
    z.object({
        ...common,
        type: z.literal("distribution"),
        source: z.enum([
            "priorities",
            "lifecycle",
            "technical",
            "inventory",
            "matching",
            "kev_priorities",
        ]),
    }),
    z.object({
        ...common,
        type: z.literal("servers"),
        limit: z.number(),
        sort: z.enum(["manual", "name", "inventory"]),
        filters: serverFilters,
    }),
    z.object({
        ...common,
        type: z.literal("findings"),
        limit: z.number(),
        filters: findingFilters,
    }),
    z.object({ ...common, type: z.literal("text"), text: z.string() }),
    z.object({
        ...common,
        type: z.enum(["summary", "inventory_quality", "database", "workflow"]),
    }),
    z.object({ ...common, type: z.literal("trend"), days: z.number() }),
]);
export const configSchema = z.object({
    version: z.literal(1),
    title: z.string(),
    description: z.string(),
    layout: z.object({ columns: z.number().int().min(1).max(3) }),
    refresh_interval_seconds: z.number(),
    widgets: z.array(widgetSchema),
});
export type DashboardConfig = z.infer<typeof configSchema>;
export type Widget = z.infer<typeof widgetSchema>;
export const dashboardSchema = z.object({
    id: z.string(),
    title: z.string(),
    yaml: z.string(),
    config: configSchema,
    version: z.number(),
    created_at: z.string(),
    updated_at: z.string(),
    can_edit: z.boolean().default(true),
    owner_username: z.string().default(""),
});
export const dashboardListSchema = z.object({
    items: z.array(
        z.object({
            id: z.string(),
            title: z.string(),
            description: z.string(),
            version: z.number(),
            updated_at: z.string(),
            can_edit: z.boolean().default(true),
            owner_username: z.string().default(""),
        }),
    ),
});
export const validationSchema = z.object({
    valid: z.boolean(),
    config: configSchema.nullable(),
    errors: z.array(z.string()),
});
export const endpoint = "/api/v1/dashboard/custom-dashboards";
export function widgetQuery(filters: Record<string, unknown>, limit: number) {
    const query = new URLSearchParams({ limit: String(limit) });
    for (const [key, value] of Object.entries(filters))
        if (value !== null && value !== undefined && value !== "")
            query.set(key, String(value));
    return query;
}
