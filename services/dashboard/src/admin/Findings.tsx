import { translateMessage, t, useLocale } from "../i18n";
import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useData, State, Card, Facts, Badge } from "../ui";
import { findingSchema, related } from "../contracts";
import {
    Allowed,
    EditForm,
    options,
    reason,
    type Field,
    type Mutation,
} from "./Form";
import { version } from "./contracts";
export default function FindingManagement() {
    useLocale();
    const { id = "" } = useParams();
    const result = useData("/api/v1/findings/" + id, findingSchema);
    const exceptions = useData(
        "/api/v1/findings/" + id + "/exceptions?limit=100",
        related,
    );
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [notice, setNotice] = useState("");
    function edit(next: Mutation) {
        setNotice("");
        setOperation(next);
    }
    const f = result.data;
    const base = "/api/v1/findings/" + id;
    const request = (
        title: string,
        section: string,
        fields: Field[],
        initial: Record<string, unknown> = {},
        stepUp = false,
        critical = false,
    ): Mutation => ({
        title: `${title}: ${f?.cve_id ?? id}`,
        path: base + "/" + section,
        method: "POST",
        fields: [...fields, { ...reason, max: 2048 }],
        initial,
        version: f ? version(f) : undefined,
        stepUp,
        critical,
    });
    return (
        <>
            <h1>
                {t("Finding bearbeiten:")} {f?.cve_id ?? id}
            </h1>
            <p>
                {t(
                    "Die technische Evidenz bleibt unverändert. Triage, Lifecycle und Risikoausnahme sind getrennte Entscheidungen.",
                )}
            </p>
            <Link to={`/findings/${id}`}>
                {t("Evidenz und Historie ansehen")}
            </Link>
            {notice && (
                <p role="status" className="notice">
                    {translateMessage(notice)}
                </p>
            )}
            {!f ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <Card title={t("Aktueller Stand")}>
                        <p>
                            <Badge value={f.latest_matching_status} />{" "}
                            <Badge value={f.lifecycle_status} />
                        </p>
                        <Facts
                            values={{
                                Finding: f.id,
                                Version: f.version,
                                Prüfstatus: f.review_state,
                                Risikoausnahme: f.has_active_exception,
                                Matching_Resultat: f.latest_matching_result_id,
                            }}
                        />
                        <div className="actions">
                            <Allowed permission="finding:update">
                                <button
                                    disabled={operation !== null}
                                    onClick={() =>
                                        edit(
                                            request(
                                                t("Triage dokumentieren"),
                                                "triage",
                                                [
                                                    {
                                                        key: "action",
                                                        label: t(
                                                            "Triageentscheidung",
                                                        ),
                                                        type: "select",
                                                        required: true,
                                                        options: [
                                                            {
                                                                id: "start",
                                                                name: t(
                                                                    "Prüfung beginnen",
                                                                ),
                                                            },
                                                            {
                                                                id: "confirm",
                                                                name: t(
                                                                    "Betroffenheit bestätigen",
                                                                ),
                                                            },
                                                            {
                                                                id: "needs_review",
                                                                name: t(
                                                                    "Prüfung erforderlich",
                                                                ),
                                                            },
                                                            {
                                                                id: "suspect_false_positive",
                                                                name: t(
                                                                    "Fehlalarm vermuten",
                                                                ),
                                                            },
                                                            {
                                                                id: "fix_check",
                                                                name: t(
                                                                    "Fixprüfung anfordern",
                                                                ),
                                                            },
                                                        ],
                                                    },
                                                ],
                                                { action: "start" },
                                            ),
                                        )
                                    }
                                >
                                    {t("Triage")}
                                </button>
                                <button
                                    disabled={operation !== null}
                                    onClick={() =>
                                        edit(
                                            request(
                                                t("Zuständigkeit zuweisen"),
                                                "assignments",
                                                [
                                                    {
                                                        key: "assignee_user_id",
                                                        label: t(
                                                            "Zulässiger Bearbeiter",
                                                        ),
                                                        type: "picker",
                                                        source: `/api/v1/dashboard/administration/findings/${id}/assignees`,
                                                    },
                                                ],
                                                {
                                                    assignee_user_id:
                                                        f.assignee_user_id,
                                                },
                                            ),
                                        )
                                    }
                                >
                                    {t("Bearbeiter zuweisen")}
                                </button>
                                <button
                                    disabled={operation !== null}
                                    onClick={() =>
                                        edit(
                                            request(
                                                t("Notiz erfassen"),
                                                "notes",
                                                [
                                                    {
                                                        key: "text",
                                                        label: t(
                                                            "Bearbeitungsnotiz",
                                                        ),
                                                        type: "textarea",
                                                        required: true,
                                                        max: 4096,
                                                    },
                                                ],
                                            ),
                                        )
                                    }
                                >
                                    {t("Notiz hinzufügen")}
                                </button>
                                <button
                                    disabled={operation !== null}
                                    onClick={() =>
                                        edit({
                                            ...request(
                                                t("Prüfung dokumentieren"),
                                                "reviews",
                                                [
                                                    {
                                                        key: "decision",
                                                        label: t(
                                                            "Prüfentscheidung",
                                                        ),
                                                        type: "select",
                                                        required: true,
                                                        options: options([
                                                            "confirmed",
                                                            "suspected_false_positive",
                                                            "needs_review",
                                                        ]),
                                                    },
                                                    {
                                                        key: "evidence",
                                                        label: t(
                                                            "Evidenzreferenz / Begründung",
                                                        ),
                                                        type: "textarea",
                                                        required: true,
                                                        min: 3,
                                                        max: 4096,
                                                    },
                                                ],
                                                { decision: "needs_review" },
                                            ),
                                            payload: (v) => ({
                                                ...v,
                                                result_id:
                                                    f.latest_matching_result_id,
                                            }),
                                        })
                                    }
                                >
                                    {t("Fehlalarmprüfung dokumentieren")}
                                </button>
                                <button
                                    disabled={operation !== null}
                                    onClick={() =>
                                        edit(
                                            request(
                                                t(
                                                    "Kompensierende Maßnahme dokumentieren",
                                                ),
                                                "mitigations",
                                                [
                                                    {
                                                        key: "description",
                                                        label: t("Maßnahme"),
                                                        type: "textarea",
                                                        required: true,
                                                        min: 3,
                                                        max: 2048,
                                                    },
                                                    {
                                                        key: "evidence",
                                                        label: t("Nachweis"),
                                                        type: "textarea",
                                                        required: true,
                                                        min: 3,
                                                        max: 4096,
                                                    },
                                                    {
                                                        key: "scope",
                                                        label: t(
                                                            "Geltungsbereich",
                                                        ),
                                                        required: true,
                                                        min: 3,
                                                        max: 256,
                                                    },
                                                ],
                                            ),
                                        )
                                    }
                                >
                                    {t("Maßnahme dokumentieren")}
                                </button>
                                <button
                                    disabled={operation !== null}
                                    onClick={() =>
                                        edit({
                                            ...request(
                                                t("Risikoausnahme beantragen"),
                                                "exceptions",
                                                [
                                                    {
                                                        key: "valid_from",
                                                        label: t("Gültig ab"),
                                                        type: "datetime-local",
                                                        required: true,
                                                    },
                                                    {
                                                        key: "valid_until",
                                                        label: t("Gültig bis"),
                                                        type: "datetime-local",
                                                        required: true,
                                                    },
                                                    {
                                                        key: "scope",
                                                        label: t(
                                                            "Geltungsbereich",
                                                        ),
                                                        type: "select",
                                                        required: true,
                                                        options: [
                                                            {
                                                                id: "basis",
                                                                name: t(
                                                                    "Aktuelle technische Grundlage",
                                                                ),
                                                            },
                                                            {
                                                                id: "episode",
                                                                name: t(
                                                                    "Aktuelle Episode",
                                                                ),
                                                            },
                                                        ],
                                                    },
                                                    {
                                                        key: "risk_context",
                                                        label: t(
                                                            "Risikokontext und Verantwortung",
                                                        ),
                                                        type: "textarea",
                                                        required: true,
                                                        min: 3,
                                                        max: 2048,
                                                    },
                                                ],
                                                { scope: "basis" },
                                            ),
                                            validate: (v) =>
                                                Date.parse(
                                                    String(v.valid_until),
                                                ) >
                                                Date.parse(String(v.valid_from))
                                                    ? null
                                                    : t(
                                                          "Ein endlicher Zeitraum mit späterem Ablauf ist erforderlich.",
                                                      ),
                                            payload: (v) => ({
                                                ...v,
                                                valid_from: new Date(
                                                    String(v.valid_from),
                                                ).toISOString(),
                                                valid_until: new Date(
                                                    String(v.valid_until),
                                                ).toISOString(),
                                            }),
                                        })
                                    }
                                >
                                    {t("Risikoausnahme beantragen")}
                                </button>
                            </Allowed>
                            <Allowed permission="finding:review:confirm">
                                <button
                                    disabled={operation !== null}
                                    onClick={() =>
                                        edit({
                                            ...request(
                                                t(
                                                    "Fehlalarm verbindlich bestätigen",
                                                ),
                                                "reviews",
                                                [
                                                    {
                                                        key: "evidence",
                                                        label: t(
                                                            "Evidenz für den Fehlalarm",
                                                        ),
                                                        type: "textarea",
                                                        required: true,
                                                        min: 3,
                                                        max: 4096,
                                                    },
                                                ],
                                                {},
                                                true,
                                                true,
                                            ),
                                            payload: (v) => ({
                                                ...v,
                                                decision:
                                                    "confirmed_false_positive",
                                                result_id:
                                                    f.latest_matching_result_id,
                                            }),
                                        })
                                    }
                                >
                                    {t("Fehlalarm bestätigen")}
                                </button>
                            </Allowed>
                            <Allowed permission="finding:close">
                                <button
                                    disabled={operation !== null}
                                    onClick={() =>
                                        edit(
                                            request(
                                                t("Finding abschließen"),
                                                "close",
                                                [],
                                                {},
                                                true,
                                                true,
                                            ),
                                        )
                                    }
                                >
                                    {t("Finding abschließen")}
                                </button>
                            </Allowed>
                        </div>
                        <p>
                            {t(
                                "Ein Abschluss wird nur mit gültigem Fixnachweis oder der vorgesehenen verifizierten Fehlalarmentscheidung zugelassen. Er setzt keinen Matching-Status.",
                            )}
                        </p>
                    </Card>
                    <Card title={t("Risikoausnahmen")}>
                        <p>{t("Eine automatische Entwarnung wird derzeit nicht unterstützt. Findings bleiben bis zur geprüften Entscheidung offen.")}</p>
                        {exceptions.data?.items.map((e) => (
                            <article className="record" key={String(e.id)}>
                                <Facts values={e} />
                                <Allowed permission="finding:exception:approve">
                                    <div className="actions">
                                        {[
                                            ["approve", t("Genehmigen")],
                                            ["reject", t("Ablehnen")],
                                            ["revoke", t("Widerrufen")],
                                        ].map(([action, title]) => (
                                            <button
                                                disabled={operation !== null}
                                                key={action}
                                                onClick={() =>
                                                    edit(
                                                        request(
                                                            t(
                                                                "Ausnahme {0} {1}",
                                                                [
                                                                    String(
                                                                        e.id,
                                                                    ),
                                                                    title.toLowerCase(),
                                                                ],
                                                            ),
                                                            `exceptions/${String(e.id)}/${action}`,
                                                            [],
                                                            {},
                                                            true,
                                                            true,
                                                        ),
                                                    )
                                                }
                                            >
                                                {title}
                                            </button>
                                        ))}
                                    </div>
                                </Allowed>
                            </article>
                        ))}
                        {exceptions.error && (
                            <State
                                error={exceptions.error}
                                reload={exceptions.reload}
                            />
                        )}
                        <p>
                            {t(
                                "Eine genehmigte Ausnahme ist keine technische Behebung; frühere Episoden und Entscheidungsversionen bleiben nachvollziehbar.",
                            )}
                        </p>
                    </Card>
                    {operation && (
                        <EditForm
                            key={operation.title}
                            operation={operation}
                            onCancel={() => setOperation(null)}
                            onReload={() => {
                                setOperation(null);
                                result.reload();
                                exceptions.reload();
                            }}
                            onDone={() => {
                                setOperation(null);
                                setNotice(
                                    t(
                                        "Finding-Entscheidung vom Server bestätigt.",
                                    ),
                                );
                                result.reload();
                                exceptions.reload();
                            }}
                        />
                    )}
                </>
            )}
        </>
    );
}
