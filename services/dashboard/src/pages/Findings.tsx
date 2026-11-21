import { t, useLocale } from "../i18n";
import Threat from "../Threat";
import AffectedSoftware from "../AffectedSoftware";
import {
    FINDINGS_CHANGED,
    FINDINGS_REFRESH,
    FINDINGS_REFRESH_INTERVAL,
} from "../finding-refresh";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { findingSchema, page, related, contextSchema } from "../contracts";
import {
    useData,
    State,
    Pagination,
    Badge,
    Card,
    Facts,
    FindingRows,
} from "../ui";
import { Allowed } from "../admin/Form";
import { date, percent } from "../format";
const findingsSchema = page(findingSchema);
export default function Findings() {
    useLocale();
    const [params, setParams] = useSearchParams();
    const offset = Number(params.get("offset")) || 0;
    const query = new URLSearchParams(params);
    query.set("limit", "25");
    const result = useData(`/api/v1/findings?${query}`, findingsSchema, {
        refreshInterval: FINDINGS_REFRESH_INTERVAL,
        refreshEvent: FINDINGS_REFRESH,
        changeEvent: FINDINGS_CHANGED,
    });
    const filter = (key: string, value: string) => {
        if (value) params.set(key, value);
        else params.delete(key);
        params.delete("offset");
        setParams(params);
    };
    return (
        <>
            <header className="page-header">
                <div>
                    <p className="eyebrow">{t("SCHWACHSTELLEN")}</p>
                    <h1>{t("Findings")}</h1>
                    <p>
                        {t(
                            "Technische Betroffenheit und Bearbeitungsstand getrennt betrachten",
                        )}
                    </p>
                </div>
                <button onClick={result.reload}>{t("Aktualisieren")}</button>
            </header>
            {result.data && result.error && (
                <p role="status" className="notice">
                    {t(
                        "Die Findings konnten zuletzt nicht aktualisiert werden. Der bisherige Stand bleibt sichtbar; die Abfrage wird erneut versucht.",
                    )}
                </p>
            )}
            <form className="filters" onSubmit={(e) => e.preventDefault()}>
                <label>
                    {t("CVE suchen")}
                    <input
                        aria-label={t("CVE suchen")}
                        placeholder="CVE-2026-1234"
                        defaultValue={params.get("cve_id") ?? ""}
                        onChange={(e) => {
                            const v = e.target.value;
                            if (!v || /^CVE-[0-9]{4}-[0-9]{4,}$/.test(v))
                                filter("cve_id", v);
                        }}
                    />
                </label>
                <label>
                    {t("Priorität")}
                    <select
                        value={params.get("priority") ?? ""}
                        onChange={(e) => filter("priority", e.target.value)}
                    >
                        <option value="">{t("Alle")}</option>
                        {["critical", "high", "medium", "low", "unrated"].map(
                            (v) => (
                                <option key={v} value={v}>
                                    {
                                        {
                                            critical: t("Kritisch"),
                                            high: t("Hoch"),
                                            medium: t("Mittel"),
                                            low: t("Niedrig"),
                                            unrated: t("Nicht bewertet"),
                                        }[v]
                                    }
                                </option>
                            ),
                        )}
                    </select>
                </label>
                <label>
                    {t("Lebenszyklus")}
                    <select
                        value={params.get("lifecycle") ?? ""}
                        onChange={(e) => filter("lifecycle", e.target.value)}
                    >
                        <option value="">{t("Alle")}</option>
                        <option value="open">{t("Offen")}</option>
                        <option value="in_progress">
                            {t("In Bearbeitung")}
                        </option>
                        <option value="resolved">{t("Behoben")}</option>
                        <option value="closed">{t("Geschlossen")}</option>
                    </select>
                </label>
                <label>
                    {t("Technische Bewertung")}
                    <select
                        value={params.get("matching_status") ?? ""}
                        onChange={(e) =>
                            filter("matching_status", e.target.value)
                        }
                    >
                        <option value="">{t("Alle")}</option>
                        <option value="affected">{t("Betroffen")}</option>
                        <option value="unknown">{t("Nicht bewertbar")}</option>
                        <option value="not_affected">
                            {t("Nicht betroffen")}
                        </option>
                        <option value="not_applicable">
                            {t("Nicht anwendbar")}
                        </option>
                    </select>
                </label>
                <label>
                    {t("Sortierung")}
                    <select
                        value={params.get("sort") ?? "priority"}
                        onChange={(e) => filter("sort", e.target.value)}
                    >
                        <option value="priority">{t("Priorität")}</option>
                        <option value="server">{t("Server")}</option>
                        <option value="cve">{t("CVE")}</option>
                        <option value="first_detected">
                            {t("Erstmals erkannt")}
                        </option>
                        <option value="deadline">{t("Frist")}</option>
                    </select>
                </label>
                <label>
                    {t("Überfällig")}
                    <select
                        value={params.get("overdue") ?? ""}
                        onChange={(e) => filter("overdue", e.target.value)}
                    >
                        <option value="">{t("Alle")}</option>
                        <option value="true">{t("Ja")}</option>
                        <option value="false">{t("Nein")}</option>
                    </select>
                </label>
                <label>
                    {t("Aktuelle KEV")}
                    <select
                        value={params.get("kev") ?? ""}
                        onChange={(e) => filter("kev", e.target.value)}
                    >
                        <option value="">{t("Alle")}</option>
                        <option value="true">{t("Ja")}</option>
                        <option value="false">{t("Nein")}</option>
                    </select>
                </label>
            </form>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <div className="card">
                    <FindingRows items={result.data.items} />
                    <Pagination
                        offset={offset}
                        total={result.data.total}
                        onChange={(n) => {
                            params.set("offset", String(n));
                            setParams(params);
                        }}
                    />
                </div>
            )}
        </>
    );
}
export function Related({ id, kind }: { id: string; kind: string }) {
    useLocale();
    const [offset, setOffset] = useState(0);
    const result = useData(
        `/api/v1/findings/${id}/${kind}?limit=25&offset=${offset}`,
        related,
    );
    return !result.data ? (
        <State error={result.error} reload={result.reload} />
    ) : (
        <>
            {result.data.items.length === 0 ? (
                <p>{t("Keine Einträge.")}</p>
            ) : (
                result.data.items.map((row, index) => (
                    <article className="record" key={String(row.id ?? index)}>
                        <Facts values={row} />
                    </article>
                ))
            )}
            <nav
                className="pagination"
                aria-label={t("{0} Seitennavigation", [kind])}
            >
                <button
                    disabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - 25))}
                >
                    {t("Zurück")}
                </button>
                <span>
                    {t("Ab Eintrag")} {offset + 1}
                </span>
                <button
                    disabled={result.data.items.length < 25}
                    onClick={() => setOffset(offset + 25)}
                >
                    {t("Weiter")}
                </button>
            </nav>
        </>
    );
}
export function FindingDetail() {
    useLocale();
    const { id = "" } = useParams();
    const result = useData(`/api/v1/findings/${id}`, findingSchema);
    const context = useData(
        `/api/v1/dashboard/security/findings/${id}/context`,
        contextSchema,
    );
    const f = result.data;
    return (
        <>
            <h1>{f?.cve_id ?? t("Findingdetails")}</h1>
            <Allowed permission="finding:update">
                <Link to={`/findings/${id}/edit`}>
                    {t("Finding bearbeiten")}
                </Link>
            </Allowed>
            {!f ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <p>
                        <Badge value={f.current_priority} />{" "}
                        <Badge value={f.latest_matching_status} />{" "}
                        <Badge value={f.lifecycle_status} />
                    </p>
                    {(!f.technical_is_current || f.is_stale) && (
                        <p className="notice">
                            {t(
                                "Die technische Bewertung ist veraltet oder beruht auf einem älteren Inventar. Dies ist keine Entwarnung.",
                            )}
                        </p>
                    )}
                    {f.has_active_exception && (
                        <p className="notice">
                            {t(
                                "Aktive Risikoausnahme: Die technische Betroffenheit bleibt unverändert.",
                            )}
                        </p>
                    )}
                    <Card title={t("Betroffene Software")}>
                        <AffectedSoftware items={f.affected_software} />
                    </Card>
                    <div className="grid-two">
                        <Card title={t("Bewertung")}>
                            <Facts
                                values={{
                                    Finding: f.id,
                                    "Matching-Resultat":
                                        f.latest_matching_result_id,
                                    Server: f.server_name ?? f.server_id,
                                    "Erstmals erkannt": date(
                                        f.first_detected_at,
                                    ),
                                    [t("Zuletzt bestätigt")]: date(
                                        f.last_confirmed_at,
                                    ),
                                    Frist: date(f.due_at),
                                    Überfällig: f.is_overdue,
                                    Prüfstatus: f.review_state,
                                    [t("Zugewiesen an")]: f.assignee_user_id,
                                }}
                            />
                        </Card>
                        <Card title={t("Risikodaten")}>
                            <h3>{t("Bedrohung")}</h3>
                            <Threat finding={f} />
                            <h3>{t("CVSS")}</h3>
                            <Facts
                                values={f.cvss ?? { Bewertung: t("Unbekannt") }}
                            />
                            <h3>{t("KEV")}</h3>
                            <p>
                                {{
                                    present: t("Im CISA-KEV-Katalog gelistet"),
                                    absent: t(
                                        "Nicht im CISA-KEV-Katalog gelistet",
                                    ),
                                    unknown: t("Unbekannt"),
                                }[f.kev_status] ?? t("Unbekannt")}{" "}
                                ·{" "}
                                {f.kev_is_current
                                    ? t("Aktuelle Quellenrevision")
                                    : t("Nicht aktuell")}
                            </p>
                            <h3>{t("EPSS")}</h3>
                            <p>
                                {percent(f.epss?.score ?? f.epss?.probability)}{" "}
                                {t(
                                    "Wahrscheinlichkeit einer Ausnutzung innerhalb von 30 Tagen",
                                )}
                            </p>
                            <Facts
                                values={
                                    f.epss
                                        ? {
                                              [t("Stand der Bewertung")]: date(
                                                  f.epss.score_date,
                                              ),
                                              Modell: f.epss.model_version,
                                              Perzentil: percent(
                                                  f.epss.percentile,
                                              ),
                                              Quellenstand: f.epss.is_stale
                                                  ? t("Veraltet")
                                                  : t("Aktuell"),
                                          }
                                        : { Quellenstand: t("Unbekannt") }
                                }
                            />
                            <p>
                                {t(
                                    "Fehlende Werte werden nicht als Null interpretiert.",
                                )}
                            </p>
                        </Card>
                        <Card title={t("Bewertungsgrundlage")}>
                            {context.data ? (
                                <>
                                    <Facts
                                        values={{
                                            ...context.data,
                                            components: undefined,
                                        }}
                                    />
                                </>
                            ) : (
                                <State
                                    error={context.error}
                                    reload={context.reload}
                                />
                            )}
                            <p>
                                {t(
                                    "Snapshot, Enrichment-Revision und Matching-Regel bestimmen die technische Aussage.",
                                )}
                            </p>
                        </Card>
                    </div>
                    {[
                        ["evidence", t("Technische Evidenz")],
                        ["history", t("Verlauf")],
                        ["episodes", t("Episoden")],
                        ["exceptions", t("Risikoausnahmen")],
                    ].map(([kind, title]) => (
                        <Card key={kind} title={title}>
                            <Related id={id} kind={kind} />
                        </Card>
                    ))}
                </>
            )}
        </>
    );
}
