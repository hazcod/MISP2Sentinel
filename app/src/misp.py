#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Connector to MISP."""

from pymisp import ExpandedPyMISP
import config

def get_misp_attributes():
    '''Method to pull the attributes (IOCs) from MISP server.'''
    misp = ExpandedPyMISP(config.MISP_DOMAIN, config.MISP_KEY, config.MISP_VERIFYCERT)
    attributes = misp.search(controller='attributes', return_format='json', **config.MISP_EVENT_FILTERS)
    return attributes['Attribute']
