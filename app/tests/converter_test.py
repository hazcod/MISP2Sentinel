#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test of converter from MISP to MS graph format."""

import unittest
import logging
import json
import glob
from datetime import datetime, timedelta, timezone
from converter import transform_misp_to_msgraph

class Config:
    '''Config class/snippet for testing, customizable.'''
    TARGET_PRODUCT = 'Azure Sentinel'
    ACTION = 'alert'
    PASSIVE_ONLY = False
    DAYS_TO_EXPIRE = 1
    def __init__(self, config_dict=None):
        if config_dict:
            self.__dict__.update(config_dict)


class TestMispEventToMsgraphConverter(unittest.TestCase):
    '''Test class for MispEventToMsgraphConverter.'''
    def test_converter_from_json_files(self):
        '''Test converter class using json files with input/desired output.'''
        self.maxDiff = None
        for test_file in glob.glob("samples/test*.json"):
            logging.info('testing file: %s', test_file)
            with open(test_file, "r") as json_file:
                json_input_and_desired_output = json.load(json_file)
                misp_attribute = json_input_and_desired_output['input']
                msgraph_ioc = transform_misp_to_msgraph(misp_attribute, Config())['msgraph_ioc']
                desired_output = json_input_and_desired_output['desired_output']
            msgraph_ioc_expiration_time = datetime.fromisoformat(msgraph_ioc['expirationDateTime'])
            desired_expiration_time = \
                (datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(days=Config.DAYS_TO_EXPIRE))
            self.assertAlmostEqual(msgraph_ioc_expiration_time, desired_expiration_time, delta=timedelta(seconds=60))
            del msgraph_ioc['expirationDateTime']
            self.assertDictEqual(msgraph_ioc, desired_output)

    def test_converter_ignored_type(self):
        '''Test for ignored type misp attributes.'''
        misp_attribute = {'type': 'btc'}
        combined_misp_msgraph_dict = transform_misp_to_msgraph(misp_attribute, Config())
        expected_dict = {
            'misp_attribute': misp_attribute,
            'msgraph_ioc': None,
            'transform_status': 'IGNORED'
        }
        self.assertDictEqual(combined_misp_msgraph_dict, expected_dict)

    def test_converter_unknown_type(self):
        '''Test for unknown type misp attributes.'''
        misp_attribute = {'type': 'unknown type'}
        combined_misp_msgraph_dict = transform_misp_to_msgraph(misp_attribute, Config())
        expected_dict = {
            'misp_attribute': misp_attribute,
            'msgraph_ioc': None,
            'transform_status': 'UNKNOWN'
        }
        self.assertDictEqual(combined_misp_msgraph_dict, expected_dict)

    def test_converter_without_type(self):
        '''Test for misp attributes without type.'''
        misp_attribute = {}
        combined_misp_msgraph_dict = transform_misp_to_msgraph(misp_attribute, Config())
        expected_dict = {
            'misp_attribute': misp_attribute,
            'msgraph_ioc': None,
            'transform_status': 'CORRUPT'
        }
        self.assertDictEqual(combined_misp_msgraph_dict, expected_dict)

    def test_converter_ignore_defender(self):
        '''Test for misp attributes without type.'''
        misp_attribute = {
            "type": "email-src",
            "value": "user@domain.org",
        }
        config_defender = Config({'TARGET_PRODUCT': "Microsoft Defender ATP"})
        combined_misp_msgraph_dict = transform_misp_to_msgraph(misp_attribute, config_defender)
        expected_dict = {
            'misp_attribute': misp_attribute,
            'msgraph_ioc': None,
            'transform_status': 'IGNORE DEFENDER'
        }
        self.assertDictEqual(combined_misp_msgraph_dict, expected_dict)

if __name__ == '__main__':
    unittest.main()
