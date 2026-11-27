import { StatusBadge, time } from "./presentation";
import { ObservationChart } from "./ObservationChart";
export { StatusBadge } from "./presentation";
export { ObservationChart } from "./ObservationChart";
import { translateMessage, t, useLocale } from "../i18n";
import { useState } from "react";
import { Link, Route, Routes, useParams } from "react-router-dom";
import { z } from "zod";
import type { components } from "../generated/status";
import { useAuth } from "../auth";
import Restarts, { RestartActions, StatusRefresh } from "./Restarts";
import { useData, State, Card, Facts, Pagination } from "../ui";
import { EditForm, Allowed, type Mutation } from "../admin/Form";
import { row, listing, type Row } from "../admin/contracts";

const state = z.enum([
    "healthy",
    "degraded",
    "unavailable",
    "unknown",
    "starting",
]);
const entity = z.object({
    schema_version: z.literal(1).default(1),
    id: z.string(),
    name: z.string(),
    kind: z.enum(["service", "pipeline"]),
    state,
    raw_state: state.nullable(),
    display_state: z.enum([
        "healthy",
        "degraded",
        "unavailable",
        "unknown",
        "starting",
        "maintenance",
    ]),
    observed_at: z.string().nullable(),
    stale: z.boolean(),
    maintenance_ids: z.array(z.string()),
});
const overviewSchema: z.ZodType<components["schemas"]["OverviewRead"]> =
    z.object({
        schema_version: z.literal(1),
        control: z
            .object({
                enabled: z.boolean().nullable(),
                sample_stale: z.boolean().default(false),
                sample_checked_at: z.string().nullable().default(null),
                state,
                workflow_state: state,
                queue_state: state,
                heartbeat_at: z.string().nullable(),
                pending: z.number().nullable(),
                processing: z.number().nullable(),
                paused: z.number().nullable(),
                failed: z.number().nullable(),
                oldest_seconds: z.number().nullable(),
                expired_leases: z.number().nullable(),
                capped: z.boolean(),
            })
            .nullable()
            .optional(),
        state,
        as_of: z.string(),
        last_observation_at: z.string().nullable(),
        coverage: z.object({ known: z.number(), total: z.number() }),
        services: z.array(entity),
        pipelines: z.array(entity),
        active_incidents: z.number(),
    });
const historySchema = listing.extend({
    samples: z.array(row),
    samples_capped: z.boolean(),
    availability: row.nullable(),
});
const base = "/api/v1/status/";
function Unavailable({
    error,
    reload,
}: {
    error: Error | null;
    reload: () => void;
}) {
    useLocale();
    return error ? (
        <section role="alert" className="notice">
            <h2>{t("Statusinformationen derzeit nicht verfügbar")}</h2>
            <p>
                {t(
                    "Der aktuelle Plattformzustand ist unbekannt. Frühere Messungen bestätigen keine aktuelle Verfügbarkeit.",
                )}
            </p>
            <p>{translateMessage(error.message)}</p>
            <button onClick={reload}>{t("Erneut prüfen")}</button>
        </section>
    ) : (
        <State error={null} reload={reload} />
    );
}
export function StatusOverview() {
    useLocale();
    const result = useData(base + "overview", overviewSchema);
    const v = result.data;
    return (
        <Restarts>
            <h1>{t("Systemstatus")}</h1>
            <p>
                {t(
                    "Technische Erreichbarkeit und fachlicher Fortschritt werden getrennt gemessen. Diese interne Beobachtung kann einen vollständigen Hostausfall nicht unabhängig bestätigen.",
                )}
            </p>
            {!v ? (
                <Unavailable error={result.error} reload={result.reload} />
            ) : (
                <>
                    <section
                        className="status-summary"
                        aria-label={t("Plattformzustand")}
                    >
                        <h2>{t("Aktueller Plattformzustand")}</h2>
                        <StatusBadge value={v.state} />
                        <p>
                            {t("Letzte Messung:")} {time(v.last_observation_at)}
                        </p>
                        <p>
                            {t("Messabdeckung:")} {v.coverage.known} {t("von")}{" "}
                            {v.coverage.total}{" "}
                            {t("Diensten mit bekanntem Zustand.")}
                        </p>
                        <p>
                            {v.active_incidents}{" "}
                            {t(
                                "offene Störungen. Die Anzeige wird ausschließlich manuell aktualisiert.",
                            )}
                        </p>
                        <StatusRefresh onRefresh={result.reload} />
                    </section>
                    {v.control && (
                        <Card title={t("Zentrale n8n-Steuerung")}>
                            <p>
                                <StatusBadge value={v.control.state} /> ·{" "}
                                {v.control.enabled === null ? t("Unbekannt") : v.control.enabled
                                    ? t("Zentrale Steuerung aktiviert")
                                    : t("Zentrale Steuerung deaktiviert")}
                            </p>
                            <p>
                                {t("Workflow:")}{" "}
                                <StatusBadge value={v.control.workflow_state} />{" "}
                                {t("· Letzter Kontakt:")}{" "}
                                {time(v.control.heartbeat_at)}
                            </p>
                            <p>
                                {t("Job-Queue:")}{" "}
                                <StatusBadge value={v.control.queue_state} /> ·{" "}
                                {v.control.pending ?? "–"} {t("wartend ·")}{" "}
                                {v.control.processing ?? "–"} {t("in Übernahme ·")}{" "}
                                {v.control.paused ?? "–"} {t("pausiert ·")}{" "}
                                {v.control.failed ?? "–"} {t("fehlgeschlagen")}
                            </p>
                            {v.control.sample_stale && <p role="status">{t("Datenstand veraltet")}</p>}
                            <p>
                                {t("Ältester fälliger Auftrag:")}{" "}
                                {v.control.oldest_seconds === null ? "–" : Math.round(v.control.oldest_seconds)}{" "}
                                {t("Sekunden.")} {v.control.expired_leases}{" "}
                                {t("abgelaufene Leases.")}
                                {v.control.capped &&
                                    t(" Die Stichprobe ist begrenzt.")}
                            </p>
                            <p>
                                {t(
                                    "Ein erreichbares n8n bestätigt noch keine Verarbeitung. Der Workflow-Kontakt wird durch den tatsächlichen Queue-Consumer aktualisiert, auch wenn die Queue leer ist.",
                                )}
                            </p>
                        </Card>
                    )}
                    <Card title={t("Dienste")}>
                        <p>
                            {t(
                                "„Gesund“ bezieht sich auf die jeweils gemessene Dimension. Eine leere Queue bestätigt keine Zustellung oder vollständige Schwachstellenbewertung.",
                            )}
                        </p>
                        <EntityList values={v.services} />
                    </Card>
                    <Card title={t("Verarbeitungspipelines")}>
                        <EntityList values={v.pipelines} />
                    </Card>
                </>
            )}
        </Restarts>
    );
}
function EntityList({ values }: { values: z.infer<typeof entity>[] }) {
    useLocale();
    const { identity } = useAuth();
    const diagnostics = identity?.permissions.includes(
        "deployment:diagnostics:read",
    );
    return values.length ? (
        <ul className="status-services">
            {values.map((v) => (
                <li key={v.id}>
                    <div>
                        {diagnostics ? (
                            <Link
                                to={
                                    v.kind === "service"
                                        ? "/status/services/" + v.id
                                        : "/status/pipelines/" +
                                          v.id.replace(/^pipeline-/, "")
                                }
                            >
                                {t(v.name)}
                            </Link>
                        ) : (
                            <strong>{t(v.name)}</strong>
                        )}
                        <p>
                            {t("Messung:")} {time(v.observed_at)}
                            {v.stale && t(" · veraltet")}
                        </p>
                    </div>
                    <div className="status-entity-controls">
                        <RestartActions entityId={v.id} />
                        <div className="status-labels">
                            <StatusBadge value={v.state} />
                            {v.maintenance_ids.length > 0 && (
                                <StatusBadge value="maintenance" />
                            )}
                        </div>
                    </div>
                </li>
            ))}
        </ul>
    ) : (
        <p>
            {t(
                "Keine Dienste registriert. Der Gesamtzustand bleibt unbekannt.",
            )}
        </p>
    );
}
function Details({ kind }: { kind: "services" | "pipelines" }) {
    useLocale();
    const { id = "" } = useParams();
    const { identity } = useAuth();
    const allowed = identity?.permissions.includes(
        "deployment:diagnostics:read",
    );
    return allowed ? (
        <DetailData key={kind + id} kind={kind} id={id} />
    ) : (
        <section role="alert">
            <h1>{t("Technische Diagnose geschützt")}</h1>
            <p>{t("Für diese Details fehlt die Diagnoseberechtigung.")}</p>
            <Link to="/status">{t("Zur Statusübersicht")}</Link>
        </section>
    );
}
function DetailData({
    kind,
    id,
}: {
    kind: "services" | "pipelines";
    id: string;
}) {
    useLocale();
    const result = useData(base + kind + "/" + id, row);
    const [hours, setHours] = useState(24);
    const [checkId, setCheckId] = useState("readiness");
    const [offset, setOffset] = useState(0);
    const history = useData(
        base +
            kind +
            "/" +
            id +
            "/history?" +
            new URLSearchParams({
                check_id: checkId,
                hours: String(hours),
                limit: "25",
                offset: String(offset),
            }),
        historySchema,
    );
    const v = result.data;
    return (
        <>
            <h1>{v ? t(String(v.name)) : t("Dienstdiagnose")}</h1>
            <Link to="/status">{t("Systemstatus")}</Link>
            {!v ? (
                <Unavailable error={result.error} reload={result.reload} />
            ) : (
                <>
                    <Card title={t("Aktueller Zustand")}>
                        <StatusBadge value={String(v.state)} />
                        {Array.isArray(v.maintenance_ids) &&
                            v.maintenance_ids.length > 0 && (
                                <StatusBadge value="maintenance" />
                            )}
                        <Facts
                            values={{
                                Rohzustand: v.raw_state,
                                Grundcode: v.reason_code,
                                Letzte_Messung: v.observed_at,
                                Letzter_Erfolg: v.last_success_at,
                                Abhängigkeitshinweise: v.dependency_hint,
                                Flapping: v.flapping,
                                Wartungsfenster: v.maintenance_ids,
                            }}
                        />
                        <p>
                            {t(
                                "Abhängigkeiten sind Diagnosehinweise, keine nachgewiesene Ursache. Wartung überschreibt den technischen Rohzustand nicht.",
                            )}
                        </p>
                    </Card>
                    <Card title={t("Prüfdimensionen")}>
                        {((v.checks as Row[]) ?? []).map((c) => (
                            <article key={String(c.check_id)}>
                                <h3>{String(c.check_id)}</h3>
                                <StatusBadge
                                    value={String(c.effective_state)}
                                />
                                <Facts
                                    values={{
                                        Rohmessung: c.result,
                                        Zeitpunkt: c.checked_at,
                                        Grundcode: c.reason_code,
                                        Dauer_ms: c.duration_ms,
                                        Definitionsversion:
                                            c.definition_version,
                                        Kennzahlen: c.metrics,
                                    }}
                                />
                            </article>
                        ))}
                        {kind === "pipelines" && (
                            <p>
                                {t(
                                    "Der Zustand folgt den Mitgliedern der Pipeline:",
                                )}{" "}
                                {String(v.dependencies)}.
                            </p>
                        )}
                    </Card>
                </>
            )}
            <Card title={t("Statushistorie")}>
                <label>
                    {t("Messreihe")}
                    <select
                        aria-label={t("Messreihe")}
                        value={checkId}
                        onChange={(e) => setCheckId(e.target.value)}
                    >
                        <option value="readiness">{t("Bereitschaft")}</option>
                        <option value="liveness">{t("Erreichbarkeit")}</option>
                        <option value="backlog">
                            {t("Verarbeitungsrückstand")}
                        </option>
                        <option value="freshness">
                            {t("Datenaktualität")}
                        </option>
                    </select>
                </label>
                <label>
                    {t("Zeitraum")}
                    <select
                        aria-label={t("Zeitraum")}
                        value={hours}
                        onChange={(e) => {
                            setHours(Number(e.target.value));
                            setOffset(0);
                        }}
                    >
                        <option value={24}>{t("24 Stunden")}</option>
                        <option value={168}>{t("7 Tage")}</option>
                        <option value={744}>{t("31 Tage")}</option>
                    </select>
                </label>
                {!history.data ? (
                    <Unavailable
                        error={history.error}
                        reload={history.reload}
                    />
                ) : (
                    <>
                        <p>
                            {t(
                                "Unbekannte Zeiten zählen nicht als verfügbar. Zwischen Messungen werden keine unbelegten Zustände interpoliert.",
                            )}
                        </p>
                        {history.data.availability && (
                            <Facts
                                values={{
                                    Bekannte_Sekunden:
                                        history.data.availability.known_seconds,
                                    Unbekannte_Sekunden:
                                        history.data.availability
                                            .unknown_seconds,
                                    Messabdeckung_Prozent:
                                        history.data.availability
                                            .coverage_percent,
                                    Verfügbarkeit_nur_in_bekannten_Zeiten_Prozent:
                                        history.data.availability
                                            .available_percent,
                                }}
                            />
                        )}
                        <ObservationChart samples={history.data.samples} />
                        {history.data.samples_capped && (
                            <p>
                                {t(
                                    "Die Zeitreihe ist auf 2000 Messpunkte begrenzt; ältere Zeiten bleiben in der Abdeckungsberechnung unbekannt.",
                                )}
                            </p>
                        )}
                        {history.data.items.map((h) => (
                            <article key={String(h.id)}>
                                <p>
                                    {time(h.observed_at)} ·{" "}
                                    <StatusBadge value={String(h.state)} />
                                </p>
                                <p>{String(h.reason_code)}</p>
                            </article>
                        ))}
                        {!history.data.items.length && (
                            <p>
                                {t(
                                    "Keine Zustandswechsel im gewählten Zeitraum.",
                                )}
                            </p>
                        )}
                        <Pagination
                            offset={offset}
                            total={history.data.total}
                            onChange={setOffset}
                        />
                    </>
                )}
            </Card>
        </>
    );
}
function Incidents() {
    useLocale();
    const [filter, setFilter] = useState("open");
    const [offset, setOffset] = useState(0);
    const result = useData(
        base +
            "incidents?" +
            new URLSearchParams({
                state: filter,
                limit: "25",
                offset: String(offset),
            }),
        listing,
    );
    return (
        <>
            <h1>{t("Störungen")}</h1>
            <label>
                {t("Störungszustand")}
                <select
                    aria-label={t("Störungszustand")}
                    value={filter}
                    onChange={(e) => {
                        setFilter(e.target.value);
                        setOffset(0);
                    }}
                >
                    <option value="open">{t("Offen")}</option>
                    <option value="resolved">{t("Wiederhergestellt")}</option>
                </select>
            </label>
            {!result.data ? (
                <Unavailable error={result.error} reload={result.reload} />
            ) : (
                <>
                    <Card title={t("Störungsverlauf")}>
                        {result.data.items.map((i) => (
                            <article key={String(i.id)}>
                                <h3>
                                    <Link
                                        to={"/status/incidents/" + String(i.id)}
                                    >
                                        {t(String(i.name))}
                                    </Link>
                                </h3>
                                <StatusBadge value={String(i.state)} />
                                <p>
                                    {String(i.reason_code)} ·{" "}
                                    {time(i.opened_at)}
                                </p>
                            </article>
                        ))}
                        {!result.data.items.length && (
                            <p>
                                {t(
                                    "Keine Störungen für diesen Filter erfasst. Fehlende Messungen beweisen keine Verfügbarkeit.",
                                )}
                            </p>
                        )}
                    </Card>
                    <Pagination
                        offset={offset}
                        total={result.data.total}
                        onChange={setOffset}
                    />
                </>
            )}
        </>
    );
}
function Incident() {
    useLocale();
    const { id = "" } = useParams();
    const [offset, setOffset] = useState(0);
    const result = useData(base + "incidents/" + id, row);
    const events = useData(
        base + "incidents/" + id + "/events?limit=25&offset=" + offset,
        listing,
    );
    return (
        <>
            <h1>{t("Störungsdetails")}</h1>
            <Link to="/status/incidents">{t("Alle Störungen")}</Link>
            {result.data ? (
                <Card title={t("Erfasste Störung")}>
                    <Facts values={result.data} />
                    <p>
                        {t(
                            "Nur bestätigte Erholungsmessungen beenden die Störung. Ein Kommentar oder eine Wartung setzt keinen gesunden Zustand.",
                        )}
                    </p>
                </Card>
            ) : (
                <Unavailable error={result.error} reload={result.reload} />
            )}
            {events.data ? (
                <Card title={t("Ereignisse")}>
                    {events.data.items.map((e) => (
                        <article key={String(e.id)}>
                            <Facts values={e} />
                        </article>
                    ))}
                    <Pagination
                        offset={offset}
                        total={events.data.total}
                        onChange={setOffset}
                    />
                </Card>
            ) : (
                <Unavailable error={events.error} reload={events.reload} />
            )}
        </>
    );
}
function Maintenance() {
    useLocale();
    const services = useData(base + "services", listing);
    const [offset, setOffset] = useState(0);
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [notice, setNotice] = useState("");
    const options = (services.data?.items ?? []).map((s) => ({
        id: String(s.id),
        name: t(String(s.name)),
    }));
    const fields = [
        {
            key: "service_ids",
            label: t("Betroffene Dienste"),
            type: "multi" as const,
            options,
        },
        {
            key: "starts_at",
            label: t("Wartungsbeginn"),
            type: "datetime-local" as const,
            required: true,
        },
        {
            key: "ends_at",
            label: t("Wartungsende"),
            type: "datetime-local" as const,
            required: true,
        },
        {
            key: "description",
            label: t("Öffentliche Beschreibung für Statusberechtigte"),
            type: "textarea" as const,
            required: true,
            min: 3,
            max: 512,
        },
        {
            key: "reason",
            label: t("Begründung"),
            type: "textarea" as const,
            required: true,
            min: 3,
            max: 256,
        },
    ];
    function edit(v?: Row) {
        setNotice("");
        setOperation({
            title: v
                ? t("Wartungsfenster bearbeiten")
                : t("Wartungsfenster planen"),
            path: base + "admin/maintenance" + (v ? "/" + String(v.id) : ""),
            method: v ? "PUT" : "POST",
            version: v ? Number(v.version) : undefined,
            critical: true,
            fields,
            initial: v
                ? {
                      ...v,
                      starts_at: localDate(String(v.starts_at)),
                      ends_at: localDate(String(v.ends_at)),
                  }
                : { service_ids: [] },
            validate: (x) =>
                !Array.isArray(x.service_ids) ||
                x.service_ids.length === 0 ||
                !Number.isFinite(Date.parse(String(x.starts_at))) ||
                !Number.isFinite(Date.parse(String(x.ends_at))) ||
                Date.parse(String(x.ends_at)) <= Date.parse(String(x.starts_at))
                    ? t(
                          "Dienste und einen endlichen, aufsteigenden Zeitraum angeben.",
                      )
                    : null,
            payload: (x) => ({
                service_ids: x.service_ids,
                starts_at: new Date(String(x.starts_at)).toISOString(),
                ends_at: new Date(String(x.ends_at)).toISOString(),
                description: x.description,
                reason: x.reason,
            }),
        });
    }
    const list = useData(
        base + "maintenance?limit=25&offset=" + offset,
        listing,
    );
    return (
        <>
            <h1>{t("Wartungsfenster")}</h1>
            <p>
                {t(
                    "Wartung kennzeichnet einen geplanten Zeitraum. Sie startet keine Dienste und unterdrückt keine technischen Fehler oder Alarme.",
                )}
            </p>
            {notice && <p role="status">{translateMessage(notice)}</p>}
            <Allowed permission="deployment:maintenance:manage">
                <button
                    disabled={!services.data || !!operation}
                    onClick={() => edit()}
                >
                    {t("Wartungsfenster planen")}
                </button>
            </Allowed>
            {!list.data ? (
                <Unavailable error={list.error} reload={list.reload} />
            ) : (
                <Card title={t("Geplante und vergangene Wartung")}>
                    {list.data.items.map((v) => (
                        <article key={String(v.id)}>
                            <h3>{String(v.description)}</h3>
                            <Facts
                                values={{
                                    Dienste: v.service_ids,
                                    Beginn: v.starts_at,
                                    Ende: v.ends_at,
                                    Abgesagt: v.cancelled,
                                    Version: v.version,
                                }}
                            />
                            <Allowed permission="deployment:maintenance:manage">
                                <button
                                    disabled={!!operation || !!v.cancelled}
                                    onClick={() => edit(v)}
                                >
                                    {t("Wartung bearbeiten")}
                                </button>
                                <button
                                    disabled={!!operation || !!v.cancelled}
                                    onClick={() =>
                                        setOperation({
                                            title: t("Wartungsfenster absagen"),
                                            path:
                                                base +
                                                "admin/maintenance/" +
                                                String(v.id),
                                            method: "DELETE",
                                            version: Number(v.version),
                                            critical: true,
                                            fields: [fields[4]],
                                            payload: (x) => ({
                                                reason: x.reason,
                                            }),
                                        })
                                    }
                                >
                                    {t("Wartung absagen")}
                                </button>
                            </Allowed>
                        </article>
                    ))}
                    {!list.data.items.length && (
                        <p>{t("Keine Wartungsfenster erfasst.")}</p>
                    )}
                    <Pagination
                        offset={offset}
                        total={list.data.total}
                        onChange={setOffset}
                    />
                </Card>
            )}
            {operation && (
                <EditForm
                    key={operation.title + operation.path}
                    operation={operation}
                    onCancel={() => setOperation(null)}
                    onReload={() => {
                        setOperation(null);
                        list.reload();
                    }}
                    onDone={() => {
                        setOperation(null);
                        setNotice(t("Wartungsmetadaten vom Server bestätigt."));
                        list.reload();
                    }}
                />
            )}
        </>
    );
}
function localDate(value: string) {
    const d = new Date(value);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000)
        .toISOString()
        .slice(0, 16);
}
export default function StatusPage() {
    useLocale();
    const { identity } = useAuth();
    if (
        !identity?.roles?.includes("admin") ||
        !identity.permissions.includes("deployment:status:read")
    )
        return (
            <section role="alert">
                <h1>{t("Statuszugriff nicht erlaubt")}</h1>
                <p>
                    {!identity?.roles?.includes("admin")
                        ? t(
                              "Der Systemstatus ist nur für Benutzer mit der Rolle admin verfügbar.",
                          )
                        : t("Die Berechtigung für den Plattformstatus fehlt.")}
                </p>
            </section>
        );
    return (
        <>
            <nav className="admin-nav" aria-label={t("Statusbereiche")}>
                <Link to="/status">{t("Übersicht")}</Link>
                <Link to="/status/incidents">{t("Störungen")}</Link>
                <Link to="/status/maintenance">{t("Wartung")}</Link>
            </nav>
            <Routes>
                <Route index element={<StatusOverview />} />
                <Route
                    path="services/:id"
                    element={<Details kind="services" />}
                />
                <Route
                    path="pipelines/:id"
                    element={<Details kind="pipelines" />}
                />
                <Route path="incidents" element={<Incidents />} />
                <Route path="incidents/:id" element={<Incident />} />
                <Route path="maintenance" element={<Maintenance />} />
            </Routes>
        </>
    );
}
