#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Converter from MISP to MS-Graph format."""

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


TYPES_MAPPING = {
    "url": "url",
}
SUPPORTED_TYPES = list(TYPES_MAPPING.keys())


def transform_iocs_misp_to_sentinel(misp_iocs: list[dict[str, any]]) -> list[SentinelIOC]:
    """Receive a 'misp attribute' and return a sentinel IOC."""
    return [
        sentinel_ioc
        for misp_ioc in misp_iocs
        if (sentinel_ioc := __transform_ioc_misp_to_sentinel(misp_ioc))
    ]


def __transform_ioc_misp_to_sentinel(misp_ioc: dict[str, any]) -> SentinelIOC:

    valid_from = datetime.fromtimestamp(int(misp_ioc["timestamp"]), timezone.utc)
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
        pattern=f"[{TYPES_MAPPING[misp_ioc['type']]}:value = '{misp_ioc['value']}']",
        patternType=TYPES_MAPPING[misp_ioc["type"]],
        validFrom=valid_from.isoformat(),
        validUntil=(valid_from + timedelta(days=AZ_DAYS_TO_EXPIRE)).isoformat(),
    )

    return sentinel_ioc
