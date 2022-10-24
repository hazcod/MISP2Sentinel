#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Push to MS graph, sentinel or defender."""


import logging

import httpx

# GRAPH_TI_INDICATORS_URL = "https://graph.microsoft.com/beta/security/tiindicators"
# GRAPH_BULK_POST_URL = f"{GRAPH_TI_INDICATORS_URL}/submitTiIndicators"


def generate_httpx_client(
    client_id: str, client_secret: str, tenant_id: str, resource: str
) -> httpx.Client:
    """Return a httpx.Client with bearer token for later requests"""
    logging.info("Generating auth token for %s for resource %s", client_id, resource)
    # Get bearer token
    data = {
        "resource": resource,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    auth_request = httpx.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
        data=data,
    )
    access_token = auth_request.json()["access_token"]

    # Create client
    headers = {"Authorization": f"Bearer {access_token}", "user-agent": "ILO_MISP/2.0"}
    client = httpx.Client(headers=headers)
    return client

    # def post_one_ioc_to_graph(self, combined_misp_msgraph_dict):
    #     """Post a list of IOCs to Sentinel/Defender (via MS Graph)."""
    #     self.__update_headers_if_needed()
    #     ioc_to_be_sent = combined_misp_msgraph_dict["msgraph_ioc"]
    #     json_response = self.__session.post(GRAPH_TI_INDICATORS_URL, json=ioc_to_be_sent).json()
    #     self.__handle_post_response(combined_misp_msgraph_dict, json_response)

    # @staticmethod
    # def __handle_post_response(combined_misp_msgraph_dict, json_response):
    #     if "error" in json_response:
    #         combined_misp_msgraph_dict["post_status"] = "ERROR"
    #         logging.error(
    #             "Error posting: %s. " "Response: %s",
    #             repr(json.dumps(combined_misp_msgraph_dict)),
    #             repr(json.dumps(json_response)),
    #         )
    #     else:
    #         combined_misp_msgraph_dict["post_status"] = "SUCCESS"

    # def __update_headers_if_needed(self):

    # @staticmethod
    # def __get_timestamp():
    #     return datetime.now().timestamp()
