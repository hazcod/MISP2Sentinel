#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""In-house script for pushing ICC MISP IOCs onto Sentinel and Defender. MS' tool is overly complex and buggy."""

import logging

import azure_ti
import converter
import misp

logging.basicConfig(level=logging.INFO)


def main():
    """Main script/function of the whole project."""
    misp_iocs = misp.get_iocs(converter.SUPPORTED_TYPES)
    recent_misp_iocs_as_sentinel = [
        msgraph_ioc
        for misp_ioc in misp_iocs
        if (msgraph_ioc := converter.transform_misp_to_msgraph(misp_ioc))
    ]

    azure_ti.sync_misp_iocs(recent_misp_iocs_as_sentinel)

    print("get msgraph and compare with misp")


if __name__ == "__main__":
    main()
