#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Converter from MISP to MS-Graph format."""

import json
import logging
from datetime import datetime, timedelta, timezone

# TODO:
# keep track of pushed IOCs
# uuid, timestamp, time expiration

# if time expiration > now, remove from list
# if uuid and timestamp exist in db, skip pushing IOC
# if uuid matches and timestamp is newer, update IOC on MSGraph


def transform_misp_to_msgraph(misp_attribute, config):
    """Receive a 'misp attribute' and return a msgraph IOC."""
    combined_misp_msgraph = __handle_type_value(misp_attribute)
    __validate_defender_fields(
        combined_misp_msgraph, config
    )  # Ignore IOC if it doesn't have a required field by defender.
    if combined_misp_msgraph["msgraph_ioc"] is not None:
        combined_misp_msgraph["msgraph_ioc"]["description"] = misp_attribute["Event"]["info"]
        combined_misp_msgraph["msgraph_ioc"]["externalId"] = misp_attribute["uuid"]
        __set_last_reported_datetime(misp_attribute, combined_misp_msgraph["msgraph_ioc"])
        __set_global_values(combined_misp_msgraph["msgraph_ioc"], config)
        __set_expiration_datetime(combined_misp_msgraph["msgraph_ioc"], config)
        __extract_tags(misp_attribute, combined_misp_msgraph["msgraph_ioc"])
        combined_misp_msgraph["transform_status"] = "SUCCESS"
    logging.debug(
        "combined_misp_msgraph after transform: %s", repr(json.dumps(combined_misp_msgraph))
    )
    return combined_misp_msgraph


REQUIRED_FIELDS_DEFENDER = set(
    ["domainName", "url", "networkDestinationIPv4", "networkDestinationIPv6", "fileHashValue"]
)


def __validate_defender_fields(combined_misp_msgraph, config):
    if config.TARGET_PRODUCT == "Microsoft Defender ATP":
        if (
            len(REQUIRED_FIELDS_DEFENDER.intersection(combined_misp_msgraph["msgraph_ioc"].keys()))
            == 0
        ):
            combined_misp_msgraph["transform_status"] = "IGNORE DEFENDER"
            combined_misp_msgraph["msgraph_ioc"] = None


def __set_last_reported_datetime(misp_attribute, msgraph_ioc):
    """Set lastReportedDateTime from the timestamp."""
    # TODO: check that the input timestamp is actually in UTC
    last_reported_datetime = datetime.fromtimestamp(int(misp_attribute["timestamp"]), timezone.utc)
    msgraph_ioc["lastReportedDateTime"] = last_reported_datetime.isoformat()


def __set_expiration_datetime(msgraph_ioc, config):
    """Set the expiration datetime."""
    expiration_datetime = datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(
        days=config.DAYS_TO_EXPIRE
    )
    msgraph_ioc["expirationDateTime"] = expiration_datetime.isoformat()


def __set_global_values(msgraph_ioc, config):
    """Set the "hardcoded"/config fiend values."""
    msgraph_ioc["action"] = config.ACTION
    msgraph_ioc["passiveOnly"] = config.PASSIVE_ONLY
    msgraph_ioc["threatType"] = "WatchList"
    msgraph_ioc["targetProduct"] = config.TARGET_PRODUCT


def __extract_tags(misp_attribute, msgraph_ioc):
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


def __handle_type_value(misp_attribute):
    """Extract and map the MISP value onto the MSGraph IOC. Returns a dict with both representations."""
    combined_misp_msgraph = {}
    combined_misp_msgraph["misp_attribute"] = misp_attribute
    (
        combined_misp_msgraph["msgraph_ioc"],
        combined_misp_msgraph["transform_status"],
    ) = __get_msgraph_ioc(misp_attribute)
    return combined_misp_msgraph


def __get_msgraph_ioc(misp_attribute):
    if "type" not in misp_attribute:
        logging.error(
            "Corrupt MISP attribute. Full MISP attribute: %s", repr(json.dumps(misp_attribute))
        )
        return (None, "CORRUPT")
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
    return (msgraph_ioc, transform_status)


HANDLER_SIMPLE_TYPES = {
    "filename": "fileName",
    "domain": "domainName",
    "hostname": "domainName",
    "url": "url",
    "link": "url",
    "email-subject": "emailSubject",
    "mutex": "fileMutexName",
}


def __simple_handler(misp_attribute):
    return {HANDLER_SIMPLE_TYPES[misp_attribute["type"]]: misp_attribute["value"]}


def __domain_ip_handler(misp_attribute):
    msgraph_ioc = {}
    splitted_value = misp_attribute["value"].split("|")
    msgraph_ioc["domainName"] = splitted_value[0]
    ip_field_name = "network" + IP_VERSION_SELECTOR(misp_attribute["value"])
    msgraph_ioc[ip_field_name] = splitted_value[1]
    return msgraph_ioc


def __email_src_handler(misp_attribute):
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


def __filehash_handler(misp_attribute):
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
NETWORK_DIRECTION = lambda type: "networkDestination" if "ip-dst" in type else "networkSource"
HANDLER_IP_TYPES = ["ip-dst", "ip-dst|port", "ip-src", "ip-src|port"]


def __network_handler(misp_attribute):
    msgraph_ioc = {}
    network_direction = NETWORK_DIRECTION(misp_attribute["type"])
    ip_version = IP_VERSION_SELECTOR(misp_attribute["value"])
    if "|" in misp_attribute["value"]:
        splitted_value = misp_attribute["value"].split("|")
        msgraph_ioc[network_direction + ip_version] = splitted_value[0]
        msgraph_ioc[network_direction + "Port"] = splitted_value[1]
    else:
        msgraph_ioc[network_direction + ip_version] = misp_attribute["value"]
    return msgraph_ioc
