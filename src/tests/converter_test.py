#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test of converter from MISP to MS graph format."""

import json

# from converter import transform_iocs_misp_to_sentinel
# from src import converter
from misp_to_sentinel import converter


def test_converter_url():
    misp_ioc = json.loads(
        """
            {
                "id": "3931551",
                "event_id": "8608",
                "category": "Network activity",
                "type": "url",
                "uuid": "d3f50f40-3b30-4909-94c0-f2e7370c71be",
                "timestamp": "1666161611",
                "value": "https://convertigoto.net/cc/flesd/YourConvertedFile59417.exe",
                "Event": {
                    "info": "Online File Converter Phishing Page Spreads RedLine Stealer"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "misp_label")

    expected_sentinel_ioc = converter.SentinelIOC(
        description=(
            "(misp_label event_id: 8608) Online File "
            "Converter Phishing Page Spreads RedLine Stealer"
        ),
        displayName="misp_label_attribute_3931551",
        externalId="d3f50f40-3b30-4909-94c0-f2e7370c71be",
        pattern="[url:value = 'https://convertigoto.net/cc/flesd/YourConvertedFile59417.exe']",
        patternType="stix",
        source="misp_label",
        threatIntelligenceTags=["misp_label_event_id_8608", "misp_label_attribute_id_3931551"],
        threatTypes=["Network activity"],
        validFrom="2022-10-19T06:40:11+00:00",
        validUntil="2022-10-21T06:40:11+00:00",
    )

    assert misp_iocs_as_sentinel[0] == expected_sentinel_ioc


def test_converter_domain():
    misp_ioc = json.loads(
        """
            {
                "id": "3931551",
                "event_id": "8608",
                "category": "Network activity",
                "type": "domain",
                "uuid": "d3f50f40-3b30-4909-94c0-f2e7370c71be",
                "timestamp": "1666161611",
                "value": "bharatbhushanaward.net",
                "Event": {
                    "info": "Online File Converter Phishing Page Spreads RedLine Stealer"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "misp_label")

    expected_sentinel_ioc = converter.SentinelIOC(
        description=(
            "(misp_label event_id: 8608) Online File "
            "Converter Phishing Page Spreads RedLine Stealer"
        ),
        displayName="misp_label_attribute_3931551",
        externalId="d3f50f40-3b30-4909-94c0-f2e7370c71be",
        pattern="[domain-name:value = 'bharatbhushanaward.net']",
        patternType="stix",
        source="misp_label",
        threatIntelligenceTags=["misp_label_event_id_8608", "misp_label_attribute_id_3931551"],
        threatTypes=["Network activity"],
        validFrom="2022-10-19T06:40:11+00:00",
        validUntil="2022-10-21T06:40:11+00:00",
    )

    assert misp_iocs_as_sentinel[0] == expected_sentinel_ioc


def test_converter_ipv4():
    misp_ioc = json.loads(
        """
            {
                "id": "3935934",
                "event_id": "8627",
                "category": "Network activity",
                "type": "ip-src",
                "uuid": "a6cc5ec3-e3c0-46a3-a92f-65142dafaf94",
                "timestamp": "1666296048",
                "value": "192.71.166.142",
                "Event": {
                    "info": "Title: October SideWinder attack on the Government of Pakistan"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "misp_label")

    expected_sentinel_ioc = converter.SentinelIOC(
        description=(
            "(misp_label event_id: 8627) Title: October SideWinder attack on the Government of "
            "Pakistan"
        ),
        displayName="misp_label_attribute_3935934",
        externalId="a6cc5ec3-e3c0-46a3-a92f-65142dafaf94",
        pattern="[ipv4-addr:value = '192.71.166.142']",
        patternType="stix",
        source="misp_label",
        threatIntelligenceTags=["misp_label_event_id_8627", "misp_label_attribute_id_3935934"],
        threatTypes=["Network activity"],
        validFrom="2022-10-20T20:00:48+00:00",
        validUntil="2022-10-22T20:00:48+00:00",
    )

    assert misp_iocs_as_sentinel[0] == expected_sentinel_ioc


def test_converter_ipv6():
    misp_ioc = json.loads(
        """
            {
                "id": "3935934",
                "event_id": "8627",
                "category": "Network activity",
                "type": "ip-src",
                "uuid": "a6cc5ec3-e3c0-46a3-a92f-65142dafaf94",
                "timestamp": "1666296048",
                "value": "2001:DB8::1",
                "Event": {
                    "info": "Title: October SideWinder attack on the Government of Pakistan"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "misp_label")

    expected_sentinel_ioc = converter.SentinelIOC(
        description=(
            "(misp_label event_id: 8627) Title: October SideWinder attack on the Government of "
            "Pakistan"
        ),
        displayName="misp_label_attribute_3935934",
        externalId="a6cc5ec3-e3c0-46a3-a92f-65142dafaf94",
        pattern="[ipv6-addr:value = '2001:DB8::1']",
        patternType="stix",
        source="misp_label",
        threatIntelligenceTags=["misp_label_event_id_8627", "misp_label_attribute_id_3935934"],
        threatTypes=["Network activity"],
        validFrom="2022-10-20T20:00:48+00:00",
        validUntil="2022-10-22T20:00:48+00:00",
    )

    assert misp_iocs_as_sentinel[0] == expected_sentinel_ioc
