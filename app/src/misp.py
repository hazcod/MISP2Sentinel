#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Connector to MISP."""
import logging

import httpx
from config import (
    MISP_BASE_URL,
    MISP_CA_BUNDLE,
    MISP_EVENT_FILTERS,
    MISP_KEY,
    MISP_TIMEOUT,
)


def get_iocs() -> dict[str, any]:
    """Method to pull the attributes (IOCs) from MISP server."""
    if not (MISP_BASE_URL and MISP_EVENT_FILTERS and MISP_KEY and MISP_TIMEOUT):
        raise Exception("Environment variables for MISP not available")

    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    url = f"{MISP_BASE_URL}/attributes/restSearch"
    data = MISP_EVENT_FILTERS
    ssl_verify = True
    if MISP_CA_BUNDLE:
        ssl_verify = httpx.create_ssl_context()
        ssl_verify.load_verify_locations(MISP_CA_BUNDLE)

    response = httpx.post(url, json=data, headers=headers, verify=ssl_verify, timeout=MISP_TIMEOUT)
    response_json = response.json()

    misp_iocs = response_json["response"]["Attribute"]
    logging.info("Retrieved %s IOCs from misp ", len(misp_iocs))

    return response_json["response"]["Attribute"]
