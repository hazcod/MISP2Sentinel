#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Push to MS graph, sentinel or defender.
"""

import logging
from os import environ

import httpx

from config import AZ_TIMEOUT

logger = logging.getLogger("misp_to_sentinel")

def generate_httpx_client(
    client_id: str, client_secret: str, tenant_id: str, resource: str
) -> httpx.Client:

    """Return a httpx.Client with bearer token for later requests"""

    logger.info("Generating auth token for %s for resource %s", client_id, resource)
    
    # Get bearer token
    data = {
        "resource": resource,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    proxy = None
    proxy_url = environ.get("http_proxy") or environ.get("https_proxy")
    if proxy_url:
        proxy = httpx.Proxy(proxy_url)

    transport = httpx.HTTPTransport(proxy=proxy, retries=3)
    with httpx.Client(transport=transport, timeout=AZ_TIMEOUT) as client:
        auth_request = client.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
            data=data,
        )

    authJSON = auth_request.json()

    if 'error' in authJSON:
        raise Exception(authJSON['error_description'])

    access_token = authJSON["access_token"]

    # Create client
    headers = {"Authorization": f"Bearer {access_token}"}
    client = httpx.Client(transport=transport, timeout=AZ_TIMEOUT, headers=headers)
    return client
