# Eigene Dashboards erstellen: YAML, Widgets und alle Datenquellen

Diese Anleitung beschreibt alle aktuell unterstützten Ressourcenquellen und
Widgettypen des Bereichs **Dashboards**. Ein Dashboard ist ein persönliches,
gespeichertes Layout aus YAML. Es verwendet die vorhandenen Daten und Rechte von
CVE Monitor. Die allgemeine Seite **Übersicht** bleibt davon unabhängig.

## Inhalt

1. [Erstellen, prüfen und speichern](#1-erstellen-prüfen-und-speichern)
2. [Grundaufbau und gemeinsame Felder](#2-grundaufbau-und-gemeinsame-felder)
3. [Alle Datenquellen und Berechtigungen](#3-alle-datenquellen-und-berechtigungen)
4. [Kennzahlen: metric](#4-kennzahlen-metric)
5. [Verteilungen: distribution](#5-verteilungen-distribution)
6. [Serverlisten: servers](#6-serverlisten-servers)
7. [Findinglisten: findings](#7-findinglisten-findings)
8. [Text und zusammengefasste Ansichten](#8-text-und-zusammengefasste-ansichten)
9. [Verlauf: trend](#9-verlauf-trend)
10. [Administrative Widgets: database und workflow](#10-administrative-widgets-database-und-workflow)
11. [Vollständige Beispiele](#11-vollständige-beispiele)
12. [Teilen, aktualisieren und Fehler beheben](#12-teilen-aktualisieren-und-fehler-beheben)

## 1. Erstellen, prüfen und speichern

1. Im Dashboard anmelden und **Dashboards** öffnen.
2. **Erstellen** wählen. Der Editor enthält einen YAML-Rumpf.
3. Einen eigenen Titel und die gewünschten Widgets eintragen oder eine
   vorhandene `.yaml`-Datei importieren.
4. **Prüfen und Vorschau** ausführen.
5. Validierungsfehler beheben und Daten sowie Darstellung in der Vorschau prüfen.
6. Mit **Speichern** dauerhaft übernehmen.
7. Das gespeicherte Dashboard im Dropdown auswählen.

**Prüfen und Vorschau** speichert noch nichts. Eine Datei zu importieren ist
ebenfalls noch keine abgeschlossene Speicherung. Mit **Bearbeiten** wird die
Konfiguration des ausgewählten Dashboards geöffnet. **YAML exportieren** lädt
den aktuellen Entwurf beziehungsweise die gespeicherte Konfiguration herunter.

Zum Einstieg eignen sich die importierbaren Vorlagen:

- [Sicherheitsübersicht](../../configuration/dashboards/security-overview.yaml)
- [Alle Widgets und Datenquellen](../../configuration/dashboards/all-resources.yaml)
- [Administrative Betriebsübersicht](../../configuration/dashboards/operations.yaml)

Die vollständige Felddefinition steht im
[JSON-Schema](../../contracts/dashboard/custom-dashboard.schema.json). Der
Server prüft zusätzlich Zusammenhänge, beispielsweise eindeutige Widget-IDs und
die erlaubten Aktualisierungsintervalle.

## 2. Grundaufbau und gemeinsame Felder

Ein kleines vollständiges Dashboard:

```yaml
version: 1
title: Mein Sicherheitsdashboard
description: Meine Server und aktuelle Aufgaben
layout:
  columns: 2
refresh_interval_seconds: 0
widgets:
  - id: active-servers
    type: metric
    title: Aktive Server
    metric: active_servers
  - id: open-findings
    type: metric
    title: Offene Findings
    metric: open_findings
  - id: notes
    type: text
    title: Hinweise
    span: 2
    text: |
      Zuerst aktuelle Inventare prüfen.
      Danach Findings fachlich bewerten und Maßnahmen dokumentieren.
```

| Feld | Pflicht / Standard | Bedeutung und Grenzen |
|---|---|---|
| `version` | Pflicht | YAML-Schemaversion; aktuell ausschließlich `1` |
| `title` | Pflicht | 1–128 Zeichen; je Besitzer normalisiert eindeutig |
| `description` | Optional, leer | Beschreibung mit höchstens 1000 Zeichen |
| `layout.columns` | Optional, `2` | 1, 2 oder 3 Spalten |
| `refresh_interval_seconds` | Optional, `0` | `0` deaktiviert die automatische Aktualisierung; sonst 60–3600 Sekunden |
| `widgets` | Pflicht | Liste mit 0–24 Widgets in der gewünschten Reihenfolge |

Alle Widgets verwenden diese gemeinsamen Felder:

| Feld | Bedeutung |
|---|---|
| `id` | Innerhalb des Dashboards eindeutig; beginnt mit einem Kleinbuchstaben, danach Kleinbuchstaben, Ziffern, `_` oder `-`; insgesamt höchstens 48 Zeichen |
| `type` | Einer der zehn unten beschriebenen Widgettypen |
| `title` | Angezeigter Titel mit 1–128 Zeichen |
| `span` | Belegte Spaltenzahl, Standard `1`; höchstens so groß wie `layout.columns` |

Die Widgetreihenfolge entspricht der YAML-Liste. Bei zwei Spalten füllt
`span: 2` die gesamte Breite. Auf schmalen Bildschirmen werden die Inhalte
untereinander dargestellt. Es gibt kein frei platzierbares Pixelraster.

Die gesamte YAML-Datei darf höchstens 32 KiB groß sein. Pro Konto sind bis zu
50 eigene Dashboards möglich. Unbekannte Felder, doppelte Schlüssel, YAML-Tags,
Anker, Aliase und zu große Verschachtelung werden abgewiesen. Zahlen und boolesche
Werte ohne Anführungszeichen schreiben, beispielsweise `limit: 10` und `kev: true`.

## 3. Alle Datenquellen und Berechtigungen

Die Ressourcenquellen sind fest in der Anwendung implementiert. In der YAML wird
der Widgettyp beziehungsweise dessen `metric` oder `source` ausgewählt; eine
URL oder Datenbankverbindung muss nicht angegeben werden.

| Widgettyp | Verfügbare Ressource | Technische Quelle | Benötigte Rechte |
|---|---|---|---|
| `metric` | Eine der acht Kennzahlen | `/api/v1/dashboard/overview` | `security:overview:read`; Findingwerte benötigen zusätzlich Findingzugriff |
| `distribution` | Eine von sechs Verteilungen | `/api/v1/dashboard/overview` | `security:overview:read`, zusätzlich Rechte für den gewählten Datenbereich |
| `servers` | Liste sichtbarer aktiver Server | `/api/v1/dashboard/security/servers` | `server:read`; Inventarfilter und Inventarsortierung zusätzlich `inventory:read` |
| `findings` | Liste sichtbarer Findings | `/api/v1/findings` | `finding:read` |
| `text` | Selbst eingegebener Hinweistext | YAML-Konfiguration | Keine zusätzliche Datenberechtigung |
| `summary` | Zusammengefasste Sicherheitskennzahlen | `/api/v1/dashboard/overview` | `security:overview:read`, Findingwerte abhängig von Findingzugriff |
| `inventory_quality` | Fehlende, alte oder unvollständige Inventare | `/api/v1/dashboard/overview` | `security:overview:read` und `inventory:read` |
| `trend` | Finding-Ereignisse über 7, 30 oder 90 Tage | `/api/v1/dashboard/overview/trends` | `security:overview:read` und `finding:read` |
| `database` | Zentraler CVE-Datenbank- und Importstatus | `/api/v1/dashboard/cve-data` | Rolle `admin` und `cve:read`; Änderungen benötigen weitere Rechte |
| `workflow` | Zentrale n8n-Verarbeitung und Steuerung | `/api/v1/dashboard/orchestration` | Rolle `admin` und `cve:read`; Steueraktionen benötigen die jeweiligen administrativen Rechte |

Der Zugang zur Dashboardverwaltung setzt `server:read` voraus. Alle Abfragen
werden serverseitig auf die zugänglichen Server und Daten begrenzt. Teilen eines
Layouts erweitert diese Berechtigungen nicht. Ein nicht berechtigtes Widget
zeigt einen entsprechenden Hinweis und gibt keine fremden Daten frei.

**Geltungsbereich beachten:** Kennzahlen, Verteilungen, `summary`,
`inventory_quality` und `trend` beziehen sich auf den jeweils berechtigten
Gesamtbestand. Gruppen-/Serverfilter werden ausschließlich bei `servers` und
`findings` unterstützt. Ein `group_id` in einer Serverliste beschränkt keine
andere Kennzahl auf derselben Seite. Es gibt keinen globalen Dashboardfilter.

`database` und `workflow` zeigen den zentralen Instanzzustand, keine Gruppe oder
einen bestimmten Server. Fehlen Rechte auf Inventar- oder Findingdaten, können
Kennzahlen nicht verfügbar sein; fehlende Daten sind keine gemessene Null.

Die auswählbaren Quellen umfassen keine frei konfigurierbaren SQL-Abfragen,
externen REST-URLs, Prometheus-, Grafana- oder Cloudflare-Datenquellen. CVE-Import,
KEV, EPSS, Ansible- und Docker-Inventare fließen über die reguläre Verarbeitung
in die vorhandenen Bestände ein. Für sie gibt es keine zusätzliche YAML-Anbindung
mit eigenen Zugangsdaten. Neue Ressourcentypen benötigen eine Implementierung
im Repository.

## 4. Kennzahlen: metric

```yaml
id: critical-count
type: metric
title: Kritische offene Findings
metric: critical
```

Zusätzlich zu den gemeinsamen Feldern ist `metric` erforderlich:

| `metric` | Bedeutung |
|---|---|
| `active_servers` | Anzahl zugänglicher aktiver Server |
| `servers_affected` | Unterschiedliche Server mit offenen oder in Bearbeitung befindlichen Findings, aktueller technischer Evidenz und Bewertung `affected` |
| `open_findings` | Findings mit Lebenszyklus `open` oder `in_progress` |
| `critical` | Offene oder in Bearbeitung befindliche Findings mit Priorität `critical` |
| `high` | Offene oder in Bearbeitung befindliche Findings mit Priorität `high` |
| `overdue` | Findings, deren aktuelle Projektion sie als überfällig kennzeichnet |
| `kev` | Findings mit vorhandenem und aktuellem KEV-Hinweis in ihrer Prioritätsbasis |
| `unknown` | Findings mit technischer Matchingbewertung `unknown` |

Die Kennzahlen haben unterschiedliche fachliche Bedingungen. `kev`, `unknown`
und Verteilungen sind nicht automatisch auf offene Findings beschränkt. Deshalb
muss ihre Summe nicht `open_findings` ergeben. Für eine ausdrücklich gefilterte
Liste den Widgettyp `findings` verwenden.

Ein `metric`-Widget unterstützt keine `filters`, kein eigenes Zeitfenster und
keine frei formulierte Berechnung.

## 5. Verteilungen: distribution

```yaml
id: priorities
type: distribution
title: Finding-Prioritäten
source: priorities
span: 2
```

`source` ist optional und hat den Standard `priorities`. Alle verfügbaren Werte:

| `source` | Inhalt | Zusätzliche Hinweise |
|---|---|---|
| `priorities` | Findings nach aktueller Priorität | `critical`, `high`, `medium`, `low`, `unrated` |
| `lifecycle` | Findings nach Lebenszyklus | `open`, `in_progress`, `resolved`, `closed` |
| `technical` | Findings nach technischer Matchingbewertung | Vorhandene Statuswerte; `potentially_affected` wird in der Darstellung zu `affected` addiert |
| `inventory` | Inventarqualität des aktiven Bestands | `missing`, `stale`, `not_configured`, `incomplete`; benötigt Inventarzugriff |
| `matching` | Aktualität der Serverbewertungen | `pending`, `outdated_matching`, `current_matching`; abhängig von Findingzugriff |
| `kev_priorities` | Prioritätsverteilung der Findings mit aktuellem KEV-Hinweis | Kein eigener KEV-Download; verwendet die gespeicherte Prioritätsbasis |

Die Werte für Inventar und Matching beschreiben Prüfmerkmale; sie sind nicht in
jedem Fall voneinander unabhängige Kategorien. Ein Inventar kann beispielsweise
zugleich veraltet und unvollständig sein.

`inventory` bedeutet:

- `missing`: kein übernommener Snapshot vorhanden;
- `stale`: Inventar als veraltet eingestuft;
- `not_configured`: Frische-/Erfassungskonfiguration als nicht eingerichtet ausgewiesen;
- `incomplete`: vorhandener letzter Snapshot nicht vollständig erfasst oder nicht
  vollständig verarbeitet.

`matching` bedeutet:

- `pending`: noch keine Bewertung vorhanden;
- `outdated_matching`: vorhandene Bewertungen sind nicht vollständig aktuell;
- `current_matching`: Bewertungen vorhanden und im ausgewiesenen Bestand aktuell.

Verteilungen besitzen keine eigenen Gruppen-, Server- oder Zeitfilter.

## 6. Serverlisten: servers

```yaml
id: web-servers
type: servers
title: Webserver mit aktuellem Inventar
span: 2
limit: 10
sort: inventory
filters:
  search: web
  distribution: Debian GNU/Linux
```

| Feld | Erlaubte Werte / Verhalten |
|---|---|
| `limit` | 1–50 Zeilen, Standard `10` |
| `sort` | `name` (Standard), `manual` oder `inventory` |
| `filters.group_id` | UUID einer eigenen persönlichen Gruppe |
| `filters.search` | Suchtext für die Serverbezeichnung, höchstens 128 Zeichen; Groß-/Kleinschreibung wird ignoriert |
| `filters.distribution` | Exakter Distributionsname aus dem Inventar, höchstens 128 Zeichen |

`sort: name` sortiert alphabetisch, `manual` verwendet die gespeicherte persönliche
Server-/Gruppenreihenfolge. `inventory` sortiert nach Erfassungszeit, neuere zuerst;
Server ohne Inventar stehen am Ende. Distributionsfilter und Inventarsortierung
benötigen `inventory:read`.

Die Tabelle zeigt Servername, Status und Zahl offener Findings. **Alle anzeigen**
öffnet die Serverseite mit den übernommenen Filtern. `limit` begrenzt nur die
Widgetliste, nicht den gesamten erfassten Bestand. Sichtbar sind standardmäßig
aktive Server; ein frei konfigurierbarer `status`-Filter wird in der Widget-YAML
nicht unterstützt.

### Gruppen-UUID ermitteln

Unter **Gruppen** die gewünschte persönliche Gruppe öffnen. Der Link zur
Serverliste enthält `group_id=…`. Diese UUID unverändert übernehmen. Der
Gruppenname selbst ist kein gültiger Filterwert.

Beispiel mit einer synthetischen UUID, die vor der Verwendung zu ersetzen ist:

```yaml
id: production-servers
type: servers
title: Meine Produktionsgruppe
sort: manual
filters:
  group_id: "11111111-1111-4111-8111-111111111111"
```

Mehrere Filter wirken gemeinsam. Eine fremde oder gelöschte persönliche Gruppe
kann einen Zugriffs- beziehungsweise Validierungsfehler verursachen. Geteilte
Layouts mit persönlichen Gruppenfiltern sind deshalb vor allem für Empfänger
geeignet, die diese Filter auf ihre eigenen Gruppen anpassen.

## 7. Findinglisten: findings

```yaml
id: urgent-findings
type: findings
title: Kritisch, offen und überfällig
span: 2
limit: 15
filters:
  priority: critical
  lifecycle: open
  overdue: true
```

| Feld | Erlaubte Werte |
|---|---|
| `limit` | 1–50 Zeilen, Standard `10` |
| `filters.server_id` | UUID eines zugänglichen Servers |
| `filters.group_id` | UUID einer eigenen persönlichen Servergruppe |
| `filters.priority` | `critical`, `high`, `medium`, `low`, `unrated` |
| `filters.lifecycle` | `open`, `in_progress`, `resolved`, `closed` |
| `filters.kev` | `true`, `false` oder ausgelassen |
| `filters.overdue` | `true`, `false` oder ausgelassen |

Die Server-UUID lässt sich dem Serverdetail-Link `/servers/<uuid>` entnehmen.
Mehrere Filter werden gemeinsam angewendet. `false` ist ein aktiver Filter und
bedeutet nicht „Filter ausgeschaltet“. Für keine Einschränkung das Feld weglassen
oder `null` verwenden. Boolesche Werte nicht als Zeichenketten schreiben.

`lifecycle: open` zeigt ausschließlich `open`, keine `in_progress`-Findings.
Für zwei getrennte Bearbeitungslisten zwei Widgets verwenden. Ohne diesen Filter
gilt die normale API-Auswahl; die YAML unterstützt keine Liste mehrerer
Lebenszykluswerte. Eine eigene Sortierreihenfolge, `offset`, technische
Statusfilter, CVE-Suche oder EPSS-Grenzwerte sind in diesem Widget nicht
konfigurierbar.

Die Tabelle enthält CVE, Server und Priorität. Ein Finding-Link öffnet die
Detailansicht; **Alle anzeigen** führt zur vollständigen Findingliste mit den
Filtern. Ein Listenfilter ist keine Änderung am Finding.

## 8. Text und zusammengefasste Ansichten

### Text: text

```yaml
id: procedure
type: text
title: Bearbeitungsablauf
span: 2
text: |
  1. Inventarstand und Evidenz prüfen.
  2. Zuständigkeit und Maßnahme dokumentieren.
  3. Nach dem Update erneut inventarisieren.
```

`text` ist Pflicht und darf 1–4000 Zeichen enthalten. `|` erhält Zeilenumbrüche.
Die Anzeige ist einfacher Text, kein ausgeführtes HTML, Skript oder eingebetteter
Markdown-Renderer. Passwörter, SSH-Schlüssel und API-Tokens gehören nicht in
Dashboardkonfigurationen, besonders wenn sie geteilt oder exportiert werden.

### Sicherheitszusammenfassung: summary

```yaml
id: summary
type: summary
title: Sicherheitslage
span: 2
```

Zeigt den Datenstand sowie aktive Server, offene Findings, betroffene Server und
überfällige Findings. Darunter folgen kritische/hohe Findings, Betroffenheit,
nicht bewertbare Findings und KEV. Es werden dieselben Daten und Bedingungen wie
bei den Kennzahlen verwendet. Keine zusätzlichen Parameter oder Filter.

### Inventarqualität: inventory_quality

```yaml
id: inventory-quality
type: inventory_quality
title: Inventarqualität
span: 2
```

Zeigt die Qualitätswerte `missing`, `stale`, `not_configured` und `incomplete`
aus dem berechtigten aktiven Bestand. Benötigt zusätzlich Inventarzugriff.
Für eine grafische Darstellung derselben Daten kann alternativ `distribution`
mit `source: inventory` verwendet werden.

## 9. Verlauf: trend

```yaml
id: finding-events
type: trend
title: Finding-Ereignisse der letzten 30 Tage
span: 2
days: 30
```

`days` ist optional, Standard `30`; erlaubt sind ausschließlich `7`, `30` oder
`90`. Die Darstellung zählt tägliche Ereignisse in UTC:

- neu erkannte Findings (`created` / angezeigte Reihe `detected`);
- behobene Findings (`resolved`);
- wieder geöffnete Findings (`reopened`);
- geschlossene Findings (`closed`).

Das sind Ereignisse, keine historischen täglichen Bestandskopien. Ein Finding
kann in einem Zeitraum mehrere unterschiedliche Ereignisse verursachen.
Die Anzeige beschränkt sich auf die weiterhin zugänglichen Findings aktiver
Server. Es gibt keinen frei konfigurierbaren Datumsbereich, Gruppenfilter oder
stündlichen Verlauf. Die Oberfläche erlaubt die angebotenen Zeitfenster auch
innerhalb des Widgets zu wechseln; `days` legt die Anfangsauswahl fest.

## 10. Administrative Widgets: database und workflow

```yaml
id: cve-data
type: database
title: CVE-Datenbank
span: 2
```

`database` bettet die CVE-Datenbankansicht ein: Quellen-/Importstand, Zählwerte,
Verarbeitungsfortschritt und je nach Rechten eine Aktualisierungsanforderung.
Es gibt keine freie SQL-Quelle und keinen Zugriff auf Datenbankpasswörter.

```yaml
id: central-control
type: workflow
title: Zentrale Verarbeitung
span: 2
```

`workflow` bettet die n8n-Steuerung ein: Zeitplaneinstellungen, Warteschlange,
aktive Abläufe und zustandsabhängige Aktionen wie Pause, Fortsetzen oder Abbruch.
Es öffnet weder die n8n-Oberfläche noch eigene Webhooks.

Beide Typen verlangen die Rolle `admin` und `cve:read`. Sichtbarkeit und
Ausführbarkeit einzelner Aktionen bleiben an zusätzliche Rechte gebunden. Die
Oberfläche dieser eingebetteten Komponenten verwendet teilweise ihre eigenen
Überschriften und Aktualisierungszyklen; ein YAML-Titel oder das globale
Refreshintervall überschreibt diese nicht vollständig. Die Komponente für die
zentrale Steuerung verlangt zusätzlich ihre administrativen Steuerrechte.

Diese Widgets eignen sich für Betreiber-/Administratordashboards. Durch Teilen
mit einem Benutzer entstehen keine administrativen Rechte.

## 11. Vollständige Beispiele

### Persönliche Arbeitsübersicht

Dieses Beispiel benötigt keine anzupassenden UUIDs:

```yaml
version: 1
title: Meine tägliche Bearbeitung
description: Aktueller Bestand und dringende Aufgaben
layout:
  columns: 2
refresh_interval_seconds: 300
widgets:
  - id: summary
    type: summary
    title: Aktueller Bestand
    span: 2
  - id: priorities
    type: distribution
    title: Prioritäten
    source: priorities
  - id: inventory
    type: inventory_quality
    title: Inventarqualität
  - id: urgent
    type: findings
    title: Offene kritische Findings
    limit: 10
    filters:
      priority: critical
      lifecycle: open
    span: 2
  - id: working
    type: findings
    title: In Bearbeitung
    limit: 10
    filters:
      lifecycle: in_progress
    span: 2
  - id: trend
    type: trend
    title: Ereignisse der letzten 30 Tage
    days: 30
    span: 2
```

### Alle Quellen ausprobieren

[all-resources.yaml](../../configuration/dashboards/all-resources.yaml) enthält
alle acht Kennzahlen, alle sechs Verteilungen, Server- und Findinglisten sowie
Text, Zusammenfassung, Inventarqualität und Verlauf. Es hat 20 Widgets und
verwendet keine installationsspezifischen UUIDs. Einzelne Widgets können
abhängig von den Rechten eingeschränkt sein.

[operations.yaml](../../configuration/dashboards/operations.yaml) ergänzt ein
separates Administratordashboard mit CVE-Datenbank und zentraler Steuerung.
Beide Vorlagen lassen sich direkt importieren und anschließend persönlich
anpassen. Sie enthalten keine Secrets oder fremden API-Zugänge.

## 12. Teilen, aktualisieren und Fehler beheben

### Teilen und Kopieren

Der Besitzer kann über **Teilen** eine kommagetrennte Liste aktiver Benutzernamen
freigeben und Freigaben wieder entfernen. Empfänger finden das Dashboard im
eigenen Dropdown. Geteilt werden YAML und Layout; die Daten werden weiterhin
mit den Rechten des jeweiligen Betrachters abgefragt.

Wer ein geteiltes Dashboard bearbeitet und speichert, muss einen Titel für eine
eigene Kopie vergeben. Das Original bleibt beim Eigentümer. Auch Administratoren
können fremde persönliche Dashboards nicht allein aufgrund ihrer Rolle lesen.

### Aktualisierung und Speicherung

`refresh_interval_seconds: 0` bedeutet manuell. **Aktualisieren** lädt gespeicherte
Konfiguration und Daten neu. Ein Intervall ab 60 Sekunden aktualisiert die
entsprechenden Ressourcen; mehrere Kennzahlen und Verteilungen nutzen eine
zusammengefasste Übersichtsanfrage. Tabellenabfragen werden zeitlich versetzt.
Die Intervalle beschaffen selbst keine neuen SSH-Inventare oder CVE-Quelldateien.

Bei vorübergehenden Abruffehlern kann der letzte Stand mit einem Hinweis sichtbar
bleiben. Eine fehlgeschlagene Aktualisierung ist kein neuer erfolgreicher
Datenstand. Ein Berechtigungsfehler darf keinen fremden Restbestand anzeigen.

YAML-Quelltext einschließlich Kommentaren wird mit Besitzer, Version und Zeitstempel
in PostgreSQL gespeichert. Containerneustarts und normale Updates überschreiben
diese Konfigurationen nicht. YAML-`version: 1` und die gespeicherte Objektversion
für Konflikterkennung sind unterschiedliche Werte.

### Typische Fehler

| Meldung / Beobachtung | Ursache und Vorgehen |
|---|---|
| Ungültiges YAML | Einrückung mit Leerzeichen, Doppelpunkte und doppelte Schlüssel prüfen |
| Unbekanntes Feld / Widget | Nur die dokumentierten Typen und deren Felder verwenden |
| Widget-ID ungültig / doppelt | Kleinbuchstaben und zulässige Zeichen verwenden; jede ID nur einmal vergeben |
| Widget breiter als Layout | `span` auf höchstens `layout.columns` begrenzen |
| Intervall wird abgewiesen | `0` oder eine ganze Zahl von 60–3600 verwenden |
| Gruppenfilter funktioniert nicht | Eigene Gruppen-UUID statt Gruppenname verwenden; bestehende Freigabe prüfen |
| Distributionsfilter bleibt leer | Den exakten Inventarnamen verwenden und Inventarzugriff prüfen |
| Kennzahl bleibt global | Gruppen-/Serverfilter gelten nur für die konkrete Liste, nicht für Kennzahlen |
| Keine Berechtigung | Rolle, Funktionsrecht und Serverfreigabe prüfen; YAML kann keine Rechte vergeben |
| Kennzahl und Liste unterscheiden sich | Lebenszyklusbedingungen, aktive Server, Objektberechtigungen und Listenlimit vergleichen |
| Daten bleiben trotz Refresh alt | Inventar- und CVE-Verarbeitung prüfen; ein UI-Refresh löst keine neue Erfassung aus |
| Titel schon vorhanden | Für das eigene Konto einen anderen Titel wählen |
| Versionskonflikt | Entwurf erhalten, aktuellen gespeicherten Stand prüfen und Änderungen bewusst erneut übernehmen |
| Speichern mit unbekanntem Ergebnis | Zuerst Auswahl/Liste prüfen, bevor ein zweiter Speichervorgang angelegt wird |

Ein Dashboard zu löschen entfernt dessen Layout und Freigaben, keine Server,
Inventare oder Findings. Die gespeicherten Konfigurationen sind Bestandteil der
Anwendungsdatenbank und damit der Instanzsicherung.

Weitere Hilfe: [Bedienungsanleitung](../bedienungsanleitung.md),
[Standardrollen](../security/default-roles.md).
