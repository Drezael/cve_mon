"""Bounded YAML, a finite widget vocabulary and no executable configuration."""

from typing import Annotated, Any, Literal
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from yaml.events import CollectionEndEvent, CollectionStartEvent
from yaml.tokens import AliasToken, AnchorToken, TagToken

MAX_BYTES = 32768


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, hide_input_in_errors=True)


class Widget(Model):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,47}$")
    title: str = Field(min_length=1, max_length=128)
    span: int = Field(default=1, ge=1, le=3, strict=True)


class MetricWidget(Widget):
    type: Literal["metric"]
    metric: Literal[
        "active_servers",
        "servers_affected",
        "open_findings",
        "critical",
        "high",
        "overdue",
        "kev",
        "unknown",
    ]


class DistributionWidget(Widget):
    type: Literal["distribution"]
    source: Literal[
        "priorities", "lifecycle", "technical", "inventory", "matching", "kev_priorities"
    ] = "priorities"


class ServerFilters(Model):
    group_id: UUID | None = None
    search: str = Field(default="", max_length=128)
    distribution: str | None = Field(default=None, max_length=128)


class ServersWidget(Widget):
    type: Literal["servers"]
    limit: int = Field(default=10, ge=1, le=50, strict=True)
    sort: Literal["manual", "name", "inventory"] = "name"
    filters: ServerFilters = Field(default_factory=ServerFilters)


class FindingFilters(Model):
    server_id: UUID | None = None
    group_id: UUID | None = None
    priority: Literal["critical", "high", "medium", "low", "unrated"] | None = None
    lifecycle: Literal["open", "in_progress", "resolved", "closed"] | None = None
    kev: bool | None = Field(default=None, strict=True)
    overdue: bool | None = Field(default=None, strict=True)


class FindingsWidget(Widget):
    type: Literal["findings"]
    limit: int = Field(default=10, ge=1, le=50, strict=True)
    filters: FindingFilters = Field(default_factory=FindingFilters)


class TextWidget(Widget):
    type: Literal["text"]
    text: str = Field(min_length=1, max_length=4000)


class OverviewWidget(Widget):
    type: Literal["summary", "inventory_quality", "database", "workflow"]


class TrendWidget(Widget):
    type: Literal["trend"]
    days: Literal[7, 30, 90] = 30


class Layout(Model):
    columns: int = Field(default=2, ge=1, le=3, strict=True)


class DashboardConfig(Model):
    version: Literal[1]
    title: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1000)
    layout: Layout = Field(default_factory=Layout)
    refresh_interval_seconds: int = Field(default=0, ge=0, le=3600, strict=True)
    widgets: list[
        Annotated[
            MetricWidget
            | DistributionWidget
            | ServersWidget
            | FindingsWidget
            | TextWidget
            | OverviewWidget
            | TrendWidget,
            Field(discriminator="type"),
        ]
    ] = Field(min_length=0, max_length=24)

    @model_validator(mode="after")
    def consistency(self) -> "DashboardConfig":
        ids = [w.id for w in self.widgets]
        if len(set(ids)) != len(ids):
            raise ValueError("Widget IDs must be unique")
        if any(w.span > self.layout.columns for w in self.widgets):
            raise ValueError("Widget span cannot exceed layout columns")
        if 0 < self.refresh_interval_seconds < 60:
            raise ValueError("Refresh must be disabled (0) or at least 60 seconds")
        return self


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate keys rather than silently replacing earlier values."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                raise ValueError("YAML mapping keys must be strings")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key == "<<":
                raise ValueError("YAML mapping keys must be strings; merge keys are unsupported")
            if key in result:
                raise ValueError(f"Duplicate YAML key at line {key_node.start_mark.line + 1}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def validate_text(value: Any) -> None:
    if isinstance(value, str):
        if any(ord(char) < 32 and char not in "\n\r\t" for char in value):
            raise ValueError("YAML text contains unsupported control characters")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("YAML text must contain valid Unicode") from None
    elif isinstance(value, dict):
        for key, item in value.items():
            validate_text(key)
            validate_text(item)
    elif isinstance(value, list):
        for item in value:
            validate_text(item)


def parse(source: str) -> DashboardConfig:
    if len(source.encode("utf-8")) > MAX_BYTES:
        raise ValueError("YAML must not exceed 32 KiB")
    try:
        for index, token in enumerate(yaml.scan(source)):
            if index > 4000:
                raise ValueError("YAML document is too complex")
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise ValueError("YAML anchors, aliases and explicit tags are unsupported")
        depth = 0
        for event in yaml.parse(source):
            if isinstance(event, CollectionStartEvent):
                depth += 1
                if depth > 12:
                    raise ValueError("YAML nesting must not exceed 12 levels")
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
        document = yaml.load(source, Loader=UniqueLoader)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ValueError("Invalid YAML" + location) from None
    if not isinstance(document, dict) or type(document.get("version")) is not int:
        raise ValueError("A dashboard mapping with integer version: 1 is required")
    validate_text(document)
    try:
        return DashboardConfig.model_validate(document)
    except ValidationError as error:
        messages = [
            ".".join(map(str, e["loc"])) + ": " + e["msg"]
            for e in error.errors(include_input=False, include_url=False)[:12]
        ]
        raise ValueError("; ".join(messages)) from None
