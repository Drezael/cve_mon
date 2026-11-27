import { useState } from "react";
import { t, useLocale } from "../i18n";
import { useData, State } from "../ui";
import { z } from "zod";
import { EditForm } from "./Form";

const path = "/api/v1/dashboard/me/ansible-vault";
import type { components } from "../generated/api";

const schema: z.ZodType<components["schemas"]["VaultState"]> = z.object({
    configured: z.boolean(),
});

export default function AnsibleVault() {
    useLocale();
    const result = useData(path, schema);
    const [editing, setEditing] = useState(false);
    const [saved, setSaved] = useState(false);
    const configured = result.data?.configured ?? false;
    return (
        <section>
            <h1>{t("Mein Ansible-Vault")}</h1>
            <p>
                {t(
                    "Hinterlege zuerst ein eigenes Vault-Passwort. SSH-Passwörter, private Schlüssel und Passphrases deiner Server werden in deinem persönlichen Vault verschlüsselt gespeichert und können nicht angezeigt oder heruntergeladen werden.",
                )}
            </p>
            <p>
                {t(
                    "Automatische Abfragen können den Vault zur Laufzeit entsperren. Das Vault-Passwort wird nicht gespeichert. Ein Passwortwechsel erhält die hinterlegten Zugangsdaten.",
                )}
            </p>
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <>
                    <p>
                        {configured
                            ? t("Dein Vault ist eingerichtet.")
                            : t("Dein Vault ist noch nicht eingerichtet.")}
                    </p>
                    {!editing && (
                        <button
                            onClick={() => {
                                setSaved(false);
                                setEditing(true);
                            }}
                        >
                            {configured
                                ? t("Vault-Passwort ändern")
                                : t("Vault einrichten")}
                        </button>
                    )}
                    {editing && (
                        <EditForm
                            operation={{
                                title: configured
                                    ? t("Vault-Passwort ändern")
                                    : t("Vault einrichten"),
                                path,
                                method: "PUT",
                                fields: [
                                    ...(configured
                                        ? [
                                              {
                                                  key: "current_password",
                                                  label: t(
                                                      "Aktuelles Vault-Passwort",
                                                  ),
                                                  type: "password" as const,
                                                  required: true,
                                                  min: 15,
                                                  max: 256,
                                              },
                                          ]
                                        : []),
                                    {
                                        key: "password",
                                        label: t("Neues Vault-Passwort"),
                                        type: "password",
                                        required: true,
                                        min: 15,
                                        max: 256,
                                    },
                                    {
                                        key: "password_confirmation",
                                        label: t("Vault-Passwort wiederholen"),
                                        type: "password",
                                        required: true,
                                        min: 15,
                                        max: 256,
                                    },
                                ],
                            }}
                            onCancel={() => setEditing(false)}
                            onReload={result.reload}
                            onDone={() => {
                                setEditing(false);
                                setSaved(true);
                                result.reload();
                            }}
                        />
                    )}
                </>
            )}
            {saved && <p role="status">{t("Vault gespeichert.")}</p>}
        </section>
    );
}
