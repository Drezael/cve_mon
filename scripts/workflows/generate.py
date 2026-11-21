"""Deterministic, credential-reference-only n8n stage workflows."""

import json
from pathlib import Path
from typing import Any, cast
from uuid import NAMESPACE_URL, uuid5

from cve_notification.control import STAGES


def definition(stage: str) -> dict[str, object]:
    identity = "cve-control-" + stage

    def http(name: str, action: str, x: int) -> dict[str, object]:
        return {
            "id": name.lower(),
            "name": name,
            "type": "n8n-nodes-base.httpRequest",
            "typeVersion": 4.2,
            "position": [x, 0],
            "retryOnFail": True,
            "maxTries": 3,
            "waitBetweenTries": 1000,
            "parameters": {
                "method": "POST",
                "url": f"https://cve-notification:8000/internal/v1/orchestration/{stage}/{action}",
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "sendBody": True,
                "specifyBody": "json",
                "jsonBody": (
                    "={{ JSON.stringify({ execution_id: String($execution.id), "
                    "workflow_id: $workflow.id, limit: 64 }) }}"
                ),
                "options": {"timeout": 10000},
            },
            "credentials": {
                "httpHeaderAuth": {"id": identity + "-v1", "name": "CVE Control " + stage}
            },
        }

    nodes: list[dict[str, object]] = [
        {
            "id": "trigger",
            "name": "Trigger",
            "type": "n8n-nodes-base.executeWorkflowTrigger",
            "typeVersion": 1.1,
            "position": [0, 0],
            "parameters": {"inputSource": "passthrough"},
        },
        http("Dispatch", "dispatch", 480),
        {
            "id": "more",
            "name": "More",
            "type": "n8n-nodes-base.if",
            "typeVersion": 2.2,
            "position": [720, 0],
            "parameters": {
                "conditions": {
                    "options": {
                        "caseSensitive": True,
                        "leftValue": "",
                        "typeValidation": "strict",
                        "version": 2,
                    },
                    "conditions": [
                        {
                            "id": "has-more",
                            "leftValue": "={{ $json.more }}",
                            "rightValue": True,
                            "operator": {
                                "type": "boolean",
                                "operation": "true",
                                "singleValue": True,
                            },
                        }
                    ],
                    "combinator": "and",
                },
                "options": {},
            },
        },
    ]

    def edge(target: str) -> dict[str, object]:
        return {"node": target, "type": "main", "index": 0}

    connections: dict[str, object] = {
        "Trigger": {"main": [[edge("Dispatch")]]},
        "Dispatch": {"main": [[edge("More")]]},
        "More": {"main": [[edge("Dispatch")], [edge("Done")]]},
    }
    nodes.append(
        {
            "id": "done",
            "name": "Done",
            "type": "n8n-nodes-base.noOp",
            "typeVersion": 1,
            "position": [960, 120],
            "parameters": {},
        }
    )
    if stage in {"import", "inventory", "status", "findings"}:
        nodes.append(http("Tick", "tick", 240))
        connections["Trigger"] = {"main": [[edge("Tick")]]}
        connections["Tick"] = {"main": [[edge("Dispatch")]]}
    return {
        "id": identity,
        "name": identity,
        "active": False,
        "versionId": str(uuid5(NAMESPACE_URL, identity + (":2" if stage == "inventory" else ":1"))),
        "nodes": nodes,
        "connections": connections,
        "settings": {
            "executionOrder": "v1",
            "executionTimeout": 60,
            "saveDataSuccessExecution": "none",
            "saveDataErrorExecution": "none",
            "saveManualExecutions": False,
            "timezone": "Europe/Berlin",
        },
        "meta": {"contractVersion": 1, "stage": stage, "role": "central-application-control"},
    }


def platform_definition() -> dict[str, object]:
    """The single visible application graph; subworkflows authorize bounded task packages."""
    identity = "cve-control-platform"
    nodes: list[dict[str, object]] = [
        {
            "id": "trigger",
            "name": "Ereignis",
            "type": "n8n-nodes-base.webhook",
            "typeVersion": 2,
            "position": [0, 0],
            "webhookId": str(uuid5(NAMESPACE_URL, identity)),
            "parameters": {
                "httpMethod": "POST",
                "path": identity,
                "authentication": "headerAuth",
                "responseMode": "onReceived",
                "options": {},
            },
            "credentials": {
                "httpHeaderAuth": {"id": "cve-control-webhook-v1", "name": "CVE Control Webhook"}
            },
        },
        {
            "id": "schedule",
            "name": "Zeitplan und Wiederaufnahme",
            "type": "n8n-nodes-base.scheduleTrigger",
            "typeVersion": 1.2,
            "position": [0, 200],
            "parameters": {"rule": {"interval": [{"field": "seconds", "secondsInterval": 10}]}},
        },
    ]
    labels = {
        "import": "V5 aktualisieren",
        "inventory": "Inventare verarbeiten",
        "enrichment": "Optionale Aufbereitung",
        "index": "CVE Suchindex",
        "matching": "Inventarabgleich",
        "findings": "Findings bewerten",
        "notifications": "Benachrichtigungen",
        "status": "System pruefen",
    }
    connections: dict[str, object] = {}

    def connect(source: str, target: str) -> None:
        connections[source] = {"main": [[{"node": target, "type": "main", "index": 0}]]}

    queue_label = "Zentrale Job Queue"
    nodes.append(
        {
            "id": "queue",
            "name": queue_label,
            "type": "n8n-nodes-base.executeWorkflow",
            "typeVersion": 1.2,
            "position": [240, 0],
            "parameters": {
                "source": "database",
                "workflowId": {"__rl": True, "value": "cve-control-queue", "mode": "id"},
                "mode": "once",
                "options": {"waitForSubWorkflow": True},
            },
        }
    )
    connect("Ereignis", queue_label)
    connect(queue_label, labels[STAGES[0]])
    connect("Zeitplan und Wiederaufnahme", queue_label)
    previous = None
    for position, stage in enumerate(STAGES):
        label = labels[stage]
        nodes.append(
            {
                "id": stage,
                "name": label,
                "type": "n8n-nodes-base.executeWorkflow",
                "typeVersion": 1.2,
                "position": [480 + position * 240, 0],
                "parameters": {
                    "source": "database",
                    "workflowId": {"__rl": True, "value": "cve-control-" + stage, "mode": "id"},
                    "mode": "once",
                    "options": {"waitForSubWorkflow": True},
                },
            }
        )
        if previous:
            connect(previous, label)
        previous = label
    return {
        "id": identity,
        "name": "CVE Plattform - zentrale Steuerung",
        "active": False,
        "versionId": str(uuid5(NAMESPACE_URL, identity + ":2")),
        "nodes": nodes,
        "connections": connections,
        "settings": {
            "executionOrder": "v1",
            "executionTimeout": 180,
            "saveDataSuccessExecution": "all",
            "saveDataErrorExecution": "all",
            "saveManualExecutions": False,
            "timezone": "Europe/Berlin",
        },
        "meta": {"contractVersion": 1, "role": "central-platform-controller"},
    }


def queue_definition() -> dict[str, Any]:
    """Visible n8n decisions over one leased FIFO message at a time."""
    identity = "cve-control-queue"
    template = cast(dict[str, Any], definition("import"))
    trigger = dict(template["nodes"][0])
    nodes = [trigger]
    connections: dict[str, Any] = {}

    def edge(name: str) -> dict[str, object]:
        return {"node": name, "type": "main", "index": 0}

    def http(name: str, action: str, x: int, y: int) -> None:
        prototype = dict(template["nodes"][1])
        prototype.update(id=action, name=name, position=[x, y])
        params = dict(prototype["parameters"])
        params["url"] = (
            "https://cve-notification:8000/internal/v1/orchestration/import/queue-" + action
        )
        params["jsonBody"] = (
            "={{ JSON.stringify({execution_id:String($execution.id),workflow_id:$workflow.id,"
            "iteration:"
            + ("$runIndex" if action == "claim" else "0")
            + ",id:$json.id,lease_token:$json.lease_token}) }}"
        )
        prototype["parameters"] = params
        nodes.append(prototype)

    http("Naechste FIFO Nachricht", "claim", 240, 0)
    connections["Trigger"] = {"main": [[edge("Naechste FIFO Nachricht")]]}
    previous = "Naechste FIFO Nachricht"
    for index, kind in enumerate(("command", "task", "result", "event")):
        name = "Typ " + kind
        condition = dict(template["nodes"][2])
        condition.update(id="kind-" + kind, name=name, position=[480 + index * 240, 0])
        condition["parameters"] = {
            "conditions": {
                "options": {
                    "caseSensitive": True,
                    "leftValue": "",
                    "typeValidation": "strict",
                    "version": 2,
                },
                "conditions": [
                    {
                        "id": kind,
                        "leftValue": "={{ $json.kind }}",
                        "rightValue": kind,
                        "operator": {"type": "string", "operation": "equals"},
                    }
                ],
                "combinator": "and",
            },
            "options": {},
        }
        nodes.append(condition)
        action = {
            "command": "Auftrag ausfuehren",
            "task": "Komponente freigeben",
            "result": "Ergebnis uebernehmen",
            "event": "Ereignis uebernehmen",
        }[kind]
        http(action, kind, 480 + index * 240, 240)
        if index == 0:
            connections[previous] = {"main": [[edge(name)]]}
        else:
            connections[previous]["main"][1] = [edge(name)]
        connections[name] = {"main": [[edge(action)], []]}
        connections[action] = {"main": [[edge("Naechste FIFO Nachricht")]]}
        previous = name
    nodes.append(
        {
            "id": "done",
            "name": "Done",
            "type": "n8n-nodes-base.noOp",
            "typeVersion": 1,
            "position": [1500, 0],
            "parameters": {},
        }
    )
    connections[previous]["main"][1] = [edge("Done")]
    return {
        "id": identity,
        "name": "CVE FIFO Job Queue",
        "active": False,
        "versionId": str(uuid5(NAMESPACE_URL, identity + ":1")),
        "nodes": nodes,
        "connections": connections,
        "settings": {
            "executionOrder": "v1",
            "executionTimeout": 120,
            "saveDataSuccessExecution": "none",
            "saveDataErrorExecution": "all",
            "saveManualExecutions": False,
            "timezone": "Europe/Berlin",
        },
        "meta": {"contractVersion": 1, "role": "central-fifo-controller"},
    }


def generate(root: Path) -> None:
    (root / "workflows/n8n/cve-control-platform.json").write_text(
        json.dumps(platform_definition(), indent=2) + "\n"
    )
    (root / "workflows/n8n/cve-control-queue.json").write_text(
        json.dumps(queue_definition(), indent=2) + "\n"
    )
    for stage in STAGES:
        (root / "workflows/n8n" / ("cve-control-" + stage + ".json")).write_text(
            json.dumps(definition(stage), indent=2) + "\n"
        )


if __name__ == "__main__":
    generate(Path(__file__).resolve().parents[2])
