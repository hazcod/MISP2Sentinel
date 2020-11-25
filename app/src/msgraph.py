#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Push to MS graph, sentinel or defender."""

import json
from datetime import datetime
from loguru import logger
from requests.packages.urllib3.util import Retry
from requests.adapters import HTTPAdapter
from requests import Session
import config

GRAPH_TI_INDICATORS_URL = 'https://graph.microsoft.com/beta/security/tiindicators'
GRAPH_BULK_POST_URL = f'{GRAPH_TI_INDICATORS_URL}/submitTiIndicators'

class MSGraphConnector():
    '''MS Graph connector class that publishes IOCs through MS Graph to Sentinel or Defender.'''
    def __init__(self):
        self.__session = Session()
        retry_strategy = Retry(
            total=5,
            backoff_factor=10,
            status_forcelist=[429, 500, 502, 503, 504, 521],
            method_whitelist=['POST']
        )
        self.__session.mount('https://', HTTPAdapter(max_retries=retry_strategy))
        self.__headers_expiration_time = 0

    # def post_ioc_bulk_to_graph(self, combined_misp_msgraph_dicts):
    #     '''Post a list of IOCs to Sentinel/Defender (via MS Graph).'''
    #     self.__update_headers_if_needed()
    #     iocs_to_be_sent = list(map(lambda d: d['msgraph_ioc'], combined_misp_msgraph_dicts))
    #     request_body = {'value': iocs_to_be_sent}
    #     logger.debug(f'Posting: {repr(json.dumps(request_body))}')
    #     json_response = requests.post(GRAPH_BULK_POST_URL, headers=self.__headers, json=request_body).json()
    #     self.__handle_post_response(json_response)

    def post_one_ioc_to_graph(self, combined_misp_msgraph_dict):
        '''Post a list of IOCs to Sentinel/Defender (via MS Graph).'''
        self.__update_headers_if_needed()
        ioc_to_be_sent = combined_misp_msgraph_dict['msgraph_ioc']
        json_response = self.__session.post(GRAPH_TI_INDICATORS_URL, json=ioc_to_be_sent).json()
        self.__handle_post_response(combined_misp_msgraph_dict, json_response)

    @staticmethod
    def __handle_post_response(combined_misp_msgraph_dict, json_response):
        if 'error' in json_response:
            combined_misp_msgraph_dict['post_status'] = "ERROR"
            logger.error( \
                f'Error posting: {repr(json.dumps(combined_misp_msgraph_dict))}. ' \
                f'Response: {repr(json.dumps(json_response))}')
        else:
            combined_misp_msgraph_dict['post_status'] = "SUCCESS"

    def __update_headers_if_needed(self):
        if self.__get_timestamp() > self.__headers_expiration_time:
            data = {
                'client_id': config.GRAPH_AUTH['client_id'],
                'client_secret': config.GRAPH_AUTH['client_secret'],
                'scope': 'https://graph.microsoft.com/.default',
                'grant_type': 'client_credentials'
            }
            access_token = self.__session.post(
                f'''https://login.microsoftonline.com/{config.GRAPH_AUTH['tenant']}/oauth2/v2.0/token''',
                data=data
            ).json()['access_token']
            self.__session.headers.update({"Authorization": f"Bearer {access_token}", 'user-agent': 'MISP/1.0'})
            self.__headers_expiration_time = self.__get_timestamp() + 3500

    @staticmethod
    def __get_timestamp():
        return datetime.now().timestamp()
