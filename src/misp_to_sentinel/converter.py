#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Converter from MISP to Sentinel format."""

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("misp_to_sentinel")


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


TYPE_MAPPINGS = {
    # IP
    "ip-dst": "ipv4/ipv6",
    "ip-dst|port": "ipv4/ipv6",
    "ip-src": "ipv4/ipv6",
    "ip-src|port": "ipv4/ipv6",
    # File hashes
    "filename|authentihash": "filename|hash",
    "filename|impfuzzy": "filename|hash",
    "filename|imphash": "filename|hash",
    "filename|md5": "filename|hash",
    "filename|pehash": "filename|hash",
    "filename|sha1": "filename|hash",
    "filename|sha224": "filename|hash",
    "filename|sha256": "filename|hash",
    "filename|sha3-224": "filename|hash",
    "filename|sha3-256": "filename|hash",
    "filename|sha3-384": "filename|hash",
    "filename|sha3-512": "filename|hash",
    "filename|sha384": "filename|hash",
    "filename|sha512": "filename|hash",
    "filename|sha512/224": "filename|hash",
    "filename|sha512/256": "filename|hash",
    "filename|ssdeep": "filename|hash",
    "filename|tlsh": "filename|hash",
    "filename|vhash": "filename|hash",
    "authentihash": "hash",
    "impfuzzy": "hash",
    "imphash": "hash",
    "md5": "hash",
    "pehash": "hash",
    "sha1": "hash",
    "sha224": "hash",
    "sha256": "hash",
    "sha3-224": "hash",
    "sha3-256": "hash",
    "sha3-384": "hash",
    "sha3-512": "hash",
    "sha384": "hash",
    "sha512": "hash",
    "sha512/224": "hash",
    "sha512/256": "hash",
    "ssdeep": "hash",
    "tlsh": "hash",
    "vhash": "hash",
    # Others
    "domain": "domain-name:value",
    "filename": "file:name",
    "url": "url:value",
}

SUPPORTED_TYPES = list(TYPE_MAPPINGS.keys())


def transform_iocs_misp_to_sentinel(
    misp_iocs: list[dict[str, any]], ioc_days_to_live: int, misp_label: str
) -> list[SentinelIOC]:
    """Receive a 'misp attribute' and return a sentinel IOC."""
    converted_iocs = [
        sentinel_ioc
        for misp_ioc in misp_iocs
        if (
            sentinel_ioc := __transform_ioc_misp_to_sentinel(
                misp_ioc, ioc_days_to_live, misp_label
            )
        )
    ]
    logger.info("Converted IOCs (MISP to Sentinel): %s", len(converted_iocs))
    return converted_iocs


def __ip_version_chooser(address: str) -> str | None:
    try:
        match ipaddress.ip_address(address).version:
            case 4:
                return "ipv4-addr:value"
            case 6:
                return "ipv6-addr:value"
    except ValueError:
        pass
    return None


def __transform_ioc_misp_to_sentinel(
    misp_ioc: dict[str, any], ioc_days_to_live: int, misp_label: str
) -> SentinelIOC | None:

    valid_from = datetime.fromtimestamp(int(misp_ioc["timestamp"]), timezone.utc)

    pattern_type = TYPE_MAPPINGS.get(misp_ioc["type"])
    if not pattern_type:
        return None
    simple_value = misp_ioc["value"].split("|")[0]  # split by pipes and take first
    pattern = f"[{pattern_type} = '{simple_value}']"

    match pattern_type:
        case "ipv4/ipv6":
            pattern = f"[{__ip_version_chooser(simple_value)} = '{simple_value}']"
        case "hash":
            pattern = f"[file:hashes.'{misp_ioc['type'].upper()}' = '{misp_ioc['value']}']"
        case "filename|hash":
            value_parts = misp_ioc["value"].split("|")
            hash_type = misp_ioc["type"].split("|")[1]
            pattern = (
                f"[file:name = '{value_parts[0]}' AND "
                f"file:hashes.'{hash_type.upper()}' = '{value_parts[1]}']"
            )

    sentinel_ioc = SentinelIOC(
        source=misp_label,
        displayName=f"{misp_label}_attribute_{misp_ioc['id']}",
        description=(
            f'({misp_label} event_id: {misp_ioc["event_id"]}) {misp_ioc["Event"]["info"]}'
        ),
        externalId=misp_ioc["uuid"],
        threatIntelligenceTags=[
            f"{misp_label}_event_id_{misp_ioc['event_id']}",
            f"{misp_label}_attribute_id_{misp_ioc['id']}",
        ],
        threatTypes=[misp_ioc["category"].strip()],
        pattern=pattern,
        patternType="stix",
        validFrom=valid_from.isoformat(),
        validUntil=(valid_from + timedelta(days=ioc_days_to_live)).isoformat(),
    )

    return sentinel_ioc
