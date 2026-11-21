import { z } from "zod";
import type { components } from "./generated/api";
export const record = z.record(z.string(), z.unknown());
export const sessionSchema = z.object({
    state: z.string(),
    display_name: z.string().optional(),
    user_id: z.string().optional(),
    mfa_verified: z.boolean().optional(),
    mfa_enabled: z.boolean().optional(),
});
export const permissionSchema = z.object({
    permissions: z.array(z.string()),
    roles: z.array(z.string()),
    user_id: z.string(),
    authorization_version: z.number(),
});
export const overviewSchema: z.ZodType<components["schemas"]["Overview"]> =
    z.object({
        generated_at: z.string(),
        scope: z.literal("authorized_servers"),
        active_servers: z.number(),
        servers_affected: z.number().nullable(),
        open_findings: z.number().nullable(),
        critical: z.number().nullable(),
        high: z.number().nullable(),
        potentially_affected: z.number().nullable(),
        unknown: z.number().nullable(),
        overdue: z.number().nullable(),
        kev: z.number().nullable(),
        priorities: z.record(z.string(), z.number()),
        lifecycle: z.record(z.string(), z.number()),
        technical: z.record(z.string(), z.number()),
        kev_priorities: z.record(z.string(), z.number()),
        inventory: z.record(z.string(), z.number().nullable()),
        matching: z.record(z.string(), z.number()),
        finding_data_available: z.boolean(),
        inventory_data_available: z.boolean(),
    });
export const trendsSchema: z.ZodType<components["schemas"]["Trends"]> =
    z.object({
        generated_at: z.string(),
        timezone: z.literal("UTC"),
        days: z.number(),
        items: z.array(
            z.object({
                day: z.string(),
                detected: z.number(),
                resolved: z.number(),
                reopened: z.number(),
                closed: z.number(),
            }),
        ),
    });
export const serverSchema = z.object({
    version: z.number().int().positive().default(1),
    can_delete: z.boolean().default(false),
    can_edit: z.boolean().default(false),
    can_scan: z.boolean().default(false),
    id: z.string(),
    display_name: z.string(),
    status: z.string(),
    primary_group_id: z.string().nullable(),
    display_order: z.number(),
    environment: z.string().nullable(),
    criticality: z.string(),
    inventory: record.nullable(),
    matching: record.nullable(),
    open_findings: z.number().nullable(),
    highest_priority: z.string().nullable(),
    groups: z.array(
        z.object({
            id: z.string(),
            name: z.string(),
            display_order: z.number(),
        }),
    ),
});
export const affectedSoftwareSchema = z.object({
    component_id: z.string(),
    name: z.string().nullable(),
    version: z.string().nullable(),
    location: z.enum(["host", "container", "unknown"]),
    container_id: z.string().nullable(),
    container_name: z.string().nullable(),
    origin: z.string().nullable(),
    target: z.string().nullable(),
    status: z.string().nullable(),
});
export const findingSchema = z
    .object({
        affected_software: z.array(affectedSoftwareSchema).default([]),
        id: z.string(),
        server_id: z.string(),
        server_name: z.string().optional(),
        cve_id: z.string(),
        current_priority: z.string(),
        lifecycle_status: z.string(),
        latest_matching_status: z.string(),
        review_state: z.string(),
        has_active_exception: z.boolean(),
        technical_is_current: z.boolean(),
        is_stale: z.boolean(),
        first_detected_at: z.string(),
        last_confirmed_at: z.string().nullable(),
        captured_at: z.string(),
        matched_at: z.string(),
        latest_matching_result_id: z.string(),
        due_at: z.string().nullable(),
        is_overdue: z.boolean(),
        cvss: record.nullable(),
        epss: record.nullable(),
        kev_status: z.string(),
        kev_is_current: z.boolean(),
        assignee_user_id: z.string().nullable(),
    })
    .passthrough();
export const groupSchema = z.object({
    id: z.string(),
    name: z.string(),
    visible_servers: z.number(),
    sort_order: z.number(),
    status: z.string(),
});
export const notificationSchema = z
    .object({
        id: z.string(),
        status: z.string(),
        reason: z.string(),
        kind: z.string(),
        created_at: z.string(),
        finding_id: z.string().nullable(),
        digest_id: z.string().nullable(),
        message_id: z.string(),
        recipient_user_id: z.string(),
        cve_id: z.string().nullable(),
        server_id: z.string().nullable(),
        server_name: z.string().nullable(),
        current_priority: z.string().nullable(),
    })
    .passthrough();
export const contextSchema = z.object({
    components: z
        .array(
            z.object({
                context: z.string(),
                installed_version: z.string().nullable().optional(),
                evidence: z
                    .array(
                        z
                            .object({
                                component: z
                                    .object({
                                        name: z.string().nullable(),
                                        container_name: z.string().nullable(),
                                        origin: z.string().nullable(),
                                        target: z.string().nullable(),
                                    })
                                    .optional(),
                            })
                            .passthrough(),
                    )
                    .default([]),
            }),
        )
        .default([]),
    finding_id: z.string(),
    snapshot_id: z.string(),
    enrichment_revision_id: z.string(),
    rule_version: z.string(),
    matched_at: z.string(),
    status: z.string(),
    coverage: record,
    data_quality: z.string().nullable(),
});
export const page = <T extends z.ZodType>(schema: T) =>
    z.object({
        items: z.array(schema),
        total: z.number(),
        limit: z.number(),
        offset: z.number(),
    });
export const related = z.object({
    items: z.array(record),
    limit: z.number().optional(),
    offset: z.number().optional(),
});
export type Finding = z.infer<typeof findingSchema>;
export type Server = z.infer<typeof serverSchema>;
export type Notification = z.infer<typeof notificationSchema>;
