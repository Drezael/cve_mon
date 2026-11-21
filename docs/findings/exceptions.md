# Risikoausnahmen

Antrag, Genehmigung, Ablehnung, Widerruf und Ablauf bleiben als immutable Datensätze erhalten.
Ein Antrag referenziert Finding, Episode, technische Basis, Antragsteller, Begründung,
Risikokontext und einen endlichen, zeitzonenbewussten Gültigkeitszeitraum. Scope basis bindet
an die konkrete Matching-Revision; scope episode gilt nur in derselben Episode. Keine
unbefristeten Standardausnahmen und keine automatische Verlängerung.

Genehmigungen benötigen finding:exception:approve und frische MFA. Die versionierte Policy
kann zusätzlich exception_four_eyes aktivieren. Die initiale Policy erfindet keinen zusätzlichen
Genehmigerzwang. Neue Episode oder abweichende Basis beendet die Anwendbarkeit entsprechend
dem erklärten Scope. Ausnahmeentscheidungen tragen eigene monotone Versionsnummern.

is_active prüft die tatsächliche Zeit und den Scope bei jedem Abruf, selbst wenn der Ablaufjob
noch nicht lief. Der persistente check_exceptions-Job schreibt den Ablauf genau einmal in
Historie und Outbox. Eine Ausnahme lässt affected, Lifecycle und Sicherheitsübersichten
bestehen. Eine Benachrichtigungsunterdrückung muss Phase 19 ausdrücklich entscheiden.
