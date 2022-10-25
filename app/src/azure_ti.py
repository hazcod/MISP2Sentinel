import logging
from datetime import datetime, timedelta, timezone

import azure_api
import httpx
from config import (
    AZ_DAYS_TO_EXPIRE,
    AZ_MISP_CLIENT_ID,
    AZ_MISP_CLIENT_SECRET,
    AZ_SENTINEL_RG,
    AZ_SENTINEL_WORKSPACE_NAME,
    AZ_SUBSCRIPTION,
    AZ_TENANT_ID,
    RECENT_NUM_DAYS,
)
from converter import SentinelIOC


def __ma_url_base() -> str:
    return (
        "https://management.azure.com/"
        f"subscriptions/{AZ_SUBSCRIPTION}/"
        f"resourceGroups/{AZ_SENTINEL_RG}/"
        f"providers/Microsoft.OperationalInsights/workspaces/{AZ_SENTINEL_WORKSPACE_NAME}/"
        "providers/Microsoft.SecurityInsights/threatIntelligence/main/"
    )


def __get_misp_ids_of_recent_ioc_in_sentinel(ma_client: httpx.Client) -> list[str]:

    url = __ma_url_base() + "queryIndicators?api-version=2022-07-01-preview"

    data = {
        "pageSize": 100000,
        "minValidUntil": (
            datetime.now(timezone.utc)
            + timedelta(days=-RECENT_NUM_DAYS)
            + timedelta(days=AZ_DAYS_TO_EXPIRE)
        ).isoformat(),
    }
    misp_ids_of_recent_ioc_in_sentinel = []
    response = ma_client.post(url, json=data)
    while True:
        response_json = response.json()
        misp_ids_of_recent_ioc_in_sentinel.extend(
            [ma_ioc["properties"]["externalId"] for ma_ioc in response_json["value"]]
        )
        if "nextLink" not in response_json:
            break
        raise Exception(
            "API (management.azure.com for querying TIs) seems to be broken: "
            "Can't get next page"
        )

    return misp_ids_of_recent_ioc_in_sentinel


def __create_api_client() -> httpx.Client:
    if not (
        AZ_MISP_CLIENT_ID
        and AZ_MISP_CLIENT_SECRET
        and AZ_TENANT_ID
        and AZ_SUBSCRIPTION
        and AZ_SENTINEL_RG
    ):
        raise Exception("AZ env variables not set.")
    ma_client = azure_api.generate_httpx_client(
        AZ_MISP_CLIENT_ID,
        AZ_MISP_CLIENT_SECRET,
        AZ_TENANT_ID,
        resource="https://management.azure.com/",
    )
    return ma_client


def __create_ti_sentinel(ma_client: httpx.Client, sentinel_ioc: SentinelIOC):
    url = __ma_url_base() + "createIndicator?api-version=2022-07-01-preview"
    data = {"kind": "indicator", "properties": sentinel_ioc.as_dict()}
    response = ma_client.post(url, json=data)
    if response.status_code not in [200, 201]:
        logging.error(
            "Couldn't create IOC in Sentinel. status_code: %s, data sent: %s. response.content: %s",
            response.status_code,
            data,
            response.content,
        )


def sync_misp_iocs(recent_misp_iocs_as_sentinel: list[dict[str, any]]):
    ma_client = __create_api_client()
    recent_ioc_in_sentinel = __get_misp_ids_of_recent_ioc_in_sentinel(ma_client)
    iocs_to_push = [
        ioc
        for ioc in recent_misp_iocs_as_sentinel
        if ioc and ioc.externalId not in recent_ioc_in_sentinel
    ]
    print(f"{len(iocs_to_push)}")
    print(f"{len(recent_ioc_in_sentinel)}")
    print(f"{len(recent_misp_iocs_as_sentinel)}")
    for sentinel_ioc in iocs_to_push:
        __create_ti_sentinel(ma_client, sentinel_ioc)