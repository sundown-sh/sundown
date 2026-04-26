"""Connector registry.

Connectors register themselves at import time via ``@register``. The
registry is the single source-of-truth for which connectors are
available and their tier (``core`` vs ``premium``). The hosted version
ships extra connectors by importing additional modules into this
registry; the OSS build only ever sees ``core``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.integrations.base import BaseConnector, ConnectorKind, ConnectorTier


@dataclass(frozen=True)
class ConnectorSpec:
    name: str
    kind: ConnectorKind
    tier: ConnectorTier
    cls: type[BaseConnector]
    config_schema: list[dict[str, Any]]
    rate_limit_per_minute: int


_REGISTRY: dict[str, ConnectorSpec] = {}


def register(cls: type[BaseConnector]) -> type[BaseConnector]:
    """Class decorator. Registers the connector under ``cls.name``."""
    if not getattr(cls, "name", None):
        raise TypeError(f"connector {cls.__name__} must set `name`")
    if not getattr(cls, "kind", None):
        raise TypeError(f"connector {cls.__name__} must set `kind`")

    spec = ConnectorSpec(
        name=cls.name,
        kind=cls.kind,
        tier=getattr(cls, "tier", ConnectorTier.CORE),
        cls=cls,
        config_schema=list(getattr(cls, "config_schema", []) or []),
        rate_limit_per_minute=int(getattr(cls, "rate_limit_per_minute", 60)),
    )
    if spec.name in _REGISTRY and _REGISTRY[spec.name].cls is not cls:
        raise ValueError(f"connector name conflict: {spec.name}")
    _REGISTRY[spec.name] = spec
    return cls


def get(name: str) -> ConnectorSpec:
    if name not in _REGISTRY:
        raise KeyError(f"unknown connector: {name}")
    return _REGISTRY[name]


def all_specs() -> list[ConnectorSpec]:
    return sorted(_REGISTRY.values(), key=lambda s: (s.kind.value, s.name))


def by_tier(tier: ConnectorTier) -> list[ConnectorSpec]:
    return [s for s in all_specs() if s.tier == tier]


def make(name: str, config: dict[str, Any]) -> BaseConnector:
    """Factory: build a connector instance from stored config."""
    return get(name).cls(config)


def to_dict(spec: ConnectorSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "kind": spec.kind.value,
        "tier": spec.tier.value,
        "rate_limit_per_minute": spec.rate_limit_per_minute,
        "config_schema": spec.config_schema,
    }


def reset_for_tests() -> None:
    """Test-only: clear the registry."""
    _REGISTRY.clear()
