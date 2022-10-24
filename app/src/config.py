"""Config variables script."""
from os import environ

RECENT_NUM_DAYS = 5

# MISP
MISP_BASE_URL = environ.get("MISP_BASE_URL")
MISP_KEY = environ.get("MISP_KEY")
MISP_CA_BUNDLE = environ.get("MISP_CA_BUNDLE")
MISP_EVENT_FILTERS = {
    "timestamp": f"{RECENT_NUM_DAYS}d",
    "published": True,
    # "limit": 1,
}
MISP_TIMEOUT = 120

# AZURE (MSGRAPH/MANAGEMENT)
AZ_AUTH_TENANT_ID = environ.get("MSGRAPH_TENANT_ID")
AZ_AUTH_CLIENT_ID = environ.get("MSGRAPH_CLIENT_ID")
AZ_AUTH_CLIENT_SECRET = environ.get("MSGRAPH_CLIENT_SECRET")

AZ_SUBSCRIPTION = environ.get("AZ_SUBSCRIPTION")
AZ_SENTINEL_RG = environ.get("AZ_SENTINEL_RG")
AZ_SENTINEL_WORKSPACE_NAME = environ.get("AZ_SENTINEL_WORKSPACE_NAME")

AZ_TARGET_PRODUCT = environ.get("MSGRAPH_TARGET_PRODUCT")
AZ_ACTION = "alert"
AZ_PASSIVE_ONLY = False
AZ_DAYS_TO_EXPIRE = (
    int(environ.get("MSGRAPH_DAYS_TO_EXPIRE")) if "MSGRAPH_DAYS_TO_EXPIRE" in environ else None
)
