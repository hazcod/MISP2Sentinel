#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Converter from MISP to Sentinel format."""

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from config import AZ_DAYS_TO_EXPIRE, MISP_LABEL


@dataclass(kw_only=True)
class SentinelIOC:
    source: str
    displayName: str
    description: str
    externalId: str
    threatIntelligenceTags: list[str]
    threatTypes: list[str]
    pattern: str
    patternType: str
    validFrom: datetime
    validUntil: datetime

    def as_dict(self) -> dict[str, str]:
        return self.__dict__


IP_TYPES = ["ip-src", "ip-dst", "ip-dst|port", "ip-src|port"]


SUPPORTED_TYPES = [*IP_TYPES, "url", "domain"]


def transform_iocs_misp_to_sentinel(misp_iocs: list[dict[str, any]]) -> list[SentinelIOC]:
    """Receive a 'misp attribute' and return a sentinel IOC."""
    return [
        sentinel_ioc
        for misp_ioc in misp_iocs
        if (sentinel_ioc := __transform_ioc_misp_to_sentinel(misp_ioc))
    ]


def __ip_version_chooser(address: str) -> str | None:
    try:
        match ipaddress.ip_address(address).version:
            case 4:
                return "ipv4-addr"
            case 6:
                return "ipv6-addr"
    except ValueError:
        pass
    return None


def __transform_ioc_misp_to_sentinel(misp_ioc: dict[str, any]) -> SentinelIOC | None:

    valid_from = datetime.fromtimestamp(int(misp_ioc["timestamp"]), timezone.utc)
    value_type = misp_ioc["type"]

    if value_type in IP_TYPES:
        value_type = __ip_version_chooser(misp_ioc["value"])
    elif value_type == "domain":
        value_type = "domain-name"

    sentinel_ioc = SentinelIOC(
        source=MISP_LABEL,
        displayName=f"{MISP_LABEL}_attribute_{misp_ioc['id']}",
        description=(
            f'({MISP_LABEL} event_id: {misp_ioc["event_id"]}) {misp_ioc["Event"]["info"]}'
        ),
        externalId=misp_ioc["uuid"],
        threatIntelligenceTags=[
            f"{MISP_LABEL}_event_id_{misp_ioc['event_id']}",
            f"{MISP_LABEL}_attribute_id_{misp_ioc['id']}",
        ],
        threatTypes=[misp_ioc["category"].strip()],
        pattern=f"[{value_type}:value = '{misp_ioc['value']}']",
        patternType="stix",
        validFrom=valid_from.isoformat(),
        validUntil=(valid_from + timedelta(days=AZ_DAYS_TO_EXPIRE)).isoformat(),
    )

    return sentinel_ioc
