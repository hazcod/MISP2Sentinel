#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Converter from MISP to MS-Graph format."""

import json
import logging
from datetime import datetime, timedelta, timezone

from config import AZ_ACTION, AZ_DAYS_TO_EXPIRE, AZ_PASSIVE_ONLY, AZ_TARGET_PRODUCT


def transform_misp_to_msgraph(misp_ioc: dict[str, any]) -> dict[str, any]:
    """Receive a 'misp attribute' and return a msgraph IOC."""
    msgraph_ioc = __get_msgraph_ioc(misp_ioc)

    if msgraph_ioc is not None:
        __add_extra_data_to_msgraph_ioc(msgraph_ioc, misp_ioc)

    logging.debug("combined_misp_msgraph after transform: %s", repr(json.dumps(msgraph_ioc)))
    return msgraph_ioc


REQUIRED_FIELDS_DEFENDER = set(
    ["domainName", "url", "networkDestinationIPv4", "networkDestinationIPv6", "fileHashValue"]
)


def __add_extra_data_to_msgraph_ioc(msgraph_ioc: dict[str, any], misp_ioc: dict[str, any]):
    """Set the "hardcoded"/config fiend values."""

    msgraph_ioc["description"] = misp_ioc["Event"]["info"]
    msgraph_ioc["externalId"] = misp_ioc["uuid"]

    msgraph_ioc["threatType"] = "WatchList"

    msgraph_ioc["action"] = AZ_ACTION
    msgraph_ioc["passiveOnly"] = AZ_PASSIVE_ONLY
    msgraph_ioc["targetProduct"] = AZ_TARGET_PRODUCT

    # assume timestamp is in UTC, set lastReportedDateTime with it (as isoformat)
    msgraph_ioc["lastReportedDateTime"] = datetime.fromtimestamp(
        int(misp_ioc["timestamp"]), timezone.utc
    ).isoformat()
    msgraph_ioc["expirationDateTime"] = (
        datetime.now(timezone.utc) + timedelta(days=AZ_DAYS_TO_EXPIRE)
    ).isoformat()

    __extract_tags(misp_ioc, msgraph_ioc)


def __extract_tags(misp_attribute: dict[str, any], msgraph_ioc: dict[str, any]):
    """Handle tags extraction."""
    list_tags = (
        [tag["name"].strip() for tag in misp_attribute["Tag"]] if "Tag" in misp_attribute else []
    )
    # TODO: remove next line if category can be mapped to ms-graph
    list_tags.append(
        misp_attribute["category"].strip()
    )  # Add category as tag, to map category somehow.
    list_tags.append(
        f"event_id_{misp_attribute['event_id']}"
    )  # Add event id as tag, to ease lookups by event id.
    msgraph_ioc["tags"] = list_tags
    for tag in list_tags:
        if tag.startswith("tlp:"):
            msgraph_ioc["tlpLevel"] = tag.split(":")[1]
        if tag.startswith("diamond-model:"):
            msgraph_ioc["diamondModel"] = tag.split(":")[1]
    if "tlpLevel" not in msgraph_ioc:
        msgraph_ioc["tlpLevel"] = "unknown"


HANDLER_IGNORED_TYPES = ["email-body", "btc", "ssdeep", "yara", "other", "vulnerability"]


def __get_msgraph_ioc(misp_attribute: dict[str, any]):
    if "type" not in misp_attribute:
        logging.error(
            "Corrupt MISP attribute. Full MISP attribute: %s", repr(json.dumps(misp_attribute))
        )
        return None
    (msgraph_ioc, transform_status) = (
        (__simple_handler(misp_attribute), "SUCCESS")
        if misp_attribute["type"] in HANDLER_SIMPLE_TYPES
        else (__filehash_handler(misp_attribute), "SUCCESS")
        if misp_attribute["type"] in HANDLER_FILEHASH_TYPES
        else (__email_src_handler(misp_attribute), "SUCCESS")
        if misp_attribute["type"] == "email-src"
        else (__domain_ip_handler(misp_attribute), "SUCCESS")
        if misp_attribute["type"] == "domain|ip"
        else (__network_handler(misp_attribute), "SUCCESS")
        if misp_attribute["type"] in HANDLER_IP_TYPES
        else (None, "IGNORED")
        if misp_attribute["type"] in HANDLER_IGNORED_TYPES
        else (None, "UNKNOWN")
    )
    if transform_status == "UNKNOWN":
        logging.error(
            "Unknown MISP attribute type. Full MISP attribute: %s",
            repr(json.dumps(misp_attribute)),
        )

    # Ignore IOC if it doesn't have a required field by defender.
    if (
        AZ_TARGET_PRODUCT == "Microsoft Defender ATP"
        and len(REQUIRED_FIELDS_DEFENDER.intersection(msgraph_ioc.keys())) == 0
    ):
        logging.error(
            "MISP IOC didn't have all data required by Defender: %s",
            repr(json.dumps(misp_attribute)),
        )
        return None

    return msgraph_ioc


HANDLER_SIMPLE_TYPES = {
    "filename": "fileName",
    "domain": "domainName",
    "hostname": "domainName",
    "url": "url",
    "link": "url",
    "email-subject": "emailSubject",
    "mutex": "fileMutexName",
}


def __simple_handler(misp_attribute: dict[str, any]) -> dict[str, any]:
    return {HANDLER_SIMPLE_TYPES[misp_attribute["type"]]: misp_attribute["value"]}


def __domain_ip_handler(misp_attribute: dict[str, any]) -> dict[str, any]:
    msgraph_ioc = {}
    splitted_value = misp_attribute["value"].split("|")
    msgraph_ioc["domainName"] = splitted_value[0]
    ip_field_name = "network" + IP_VERSION_SELECTOR(misp_attribute["value"])
    msgraph_ioc[ip_field_name] = splitted_value[1]
    return msgraph_ioc


def __email_src_handler(misp_attribute: dict[str, any]) -> dict[str, any]:
    msgraph_ioc = {}
    msgraph_ioc["emailSenderAddress"] = misp_attribute["value"]
    msgraph_ioc["emailSourceDomain"] = misp_attribute["value"].split("@")[1]
    return msgraph_ioc


HANDLER_FILEHASH_TYPES = [
    "filename|md5",
    "filename|sha1",
    "filename|sha256",
    "md5",
    "sha1",
    "sha256",
]


def __filehash_handler(misp_attribute: dict[str, any]) -> dict[str, any]:
    msgraph_ioc = {}
    msgraph_ioc["fileHashType"] = misp_attribute["type"].replace("filename|", "")
    if "|" in misp_attribute["value"]:
        splitted_value = misp_attribute["value"].split("|")
        msgraph_ioc["fileName"] = splitted_value[0]
        msgraph_ioc["fileHashValue"] = splitted_value[1]
    else:
        msgraph_ioc["fileHashValue"] = misp_attribute["value"]
    return msgraph_ioc


IP_VERSION_SELECTOR = lambda value: "IPv4" if "." in value else "IPv6"
NETWORK_DIRECTION = {
    "ip-dst": "networkDestination",
    "ip-src": "networkSource",
}
HANDLER_IP_TYPES = ["ip-dst", "ip-dst|port", "ip-src", "ip-src|port"]


def __network_handler(misp_attribute: dict[str, any]) -> dict[str, any]:
    msgraph_ioc = {}
    network_direction = NETWORK_DIRECTION[misp_attribute["type"].split("|")[0]]
    ip_version = IP_VERSION_SELECTOR(misp_attribute["value"])
    if "|" in misp_attribute["value"]:
        splitted_value = misp_attribute["value"].split("|")
        msgraph_ioc[network_direction + ip_version] = splitted_value[0]
        msgraph_ioc[network_direction + "Port"] = splitted_value[1]
    else:
        msgraph_ioc[network_direction + ip_version] = misp_attribute["value"]
    return msgraph_ioc
