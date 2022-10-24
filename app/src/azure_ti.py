import json
from datetime import datetime, timedelta, timezone

import azure_api
from config import (
    AZ_AUTH_CLIENT_ID,
    AZ_AUTH_CLIENT_SECRET,
    AZ_AUTH_TENANT_ID,
    AZ_DAYS_TO_EXPIRE,
    AZ_SENTINEL_RG,
    AZ_SENTINEL_WORKSPACE_NAME,
    AZ_SUBSCRIPTION,
    RECENT_NUM_DAYS,
)


def __get_misp_ids_of_recent_ioc_in_sentinel() -> list[str]:
    if not (
        AZ_AUTH_CLIENT_ID
        and AZ_AUTH_CLIENT_SECRET
        and AZ_AUTH_TENANT_ID
        and AZ_SUBSCRIPTION
        and AZ_SENTINEL_RG
    ):
        raise Exception("AZ env variables not set.")
    ma_client = azure_api.generate_httpx_client(
        AZ_AUTH_CLIENT_ID,
        AZ_AUTH_CLIENT_SECRET,
        AZ_AUTH_TENANT_ID,
        resource="https://management.azure.com/",
    )
    url = (
        "https://management.azure.com/"
        f"subscriptions/{AZ_SUBSCRIPTION}/"
        f"resourceGroups/{AZ_SENTINEL_RG}/"
        f"providers/Microsoft.OperationalInsights/workspaces/{AZ_SENTINEL_WORKSPACE_NAME}/"
        "providers/Microsoft.SecurityInsights/threatIntelligence/main/"
        "queryIndicators?api-version=2021-10-01"
    )

    data = {
        "pageSize": 100,
        "minValidUntil": (
            datetime.now(timezone.utc)
            + timedelta(days=-RECENT_NUM_DAYS)
            + timedelta(days=AZ_DAYS_TO_EXPIRE)
        ).isoformat(),
        "sortBy": [{"itemKey": "lastUpdatedTimeUtc", "sortOrder": "descending"}],
    }
    misp_ids_of_recent_ioc_in_sentinel = []
    response = ma_client.post(url, json=data)
    while True:
        response_json = response.json()
        misp_ids_of_recent_ioc_in_sentinel.extend(
            [
                ma_ioc["properties"]["extensions"]["isg-source-ext"]["externalId"]
                for ma_ioc in response_json["value"]
            ]
        )
        if "nextLink" not in response_json:
            break
        print(response_json["nextLink"])
        response = ma_client.get(response_json["nextLink"])

    print(json.dumps(misp_ids_of_recent_ioc_in_sentinel, indent=2))
    # print(json.dumps(response_json, indent=2))
    return


def sync_misp_iocs(misp_iocs: list[dict[str, any]]):
    # msgraph_iocs = list(map(converter.transform_misp_to_msgraph, misp_iocs))
    # msgraph_client = azure_api.generate_httpx_client(
    #     GRAPH_AUTH_CLIENT_ID,
    #     GRAPH_AUTH_CLIENT_SECRET,
    #     GRAPH_AUTH_TENANT_ID,
    #     resource="https://graph.microsoft.com",
    # )
    # print(
    #     json.dumps(
    #         msgraph_client.get(
    #             url="https://graph.microsoft.com/beta/security/tiIndicators"
    #         ).json(),
    #         indent=2,
    #     )
    # )
    __get_misp_ids_of_recent_ioc_in_sentinel()
