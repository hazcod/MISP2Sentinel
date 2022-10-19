"""Config variables script."""
from os import environ

# MISP
MISP_BASE_URL = environ.get("MISP_BASE_URL")
MISP_KEY = environ.get("MISP_KEY")
MISP_CA_BUNDLE = environ.get("MISP_CA_BUNDLE")
MISP_EVENT_FILTERS = {
    "timestamp": "5h",
    "published": True,
}
MISP_TIMEOUT = 120

# GRAPH
GRAPH_AUTH = {
    "tenant": environ.get("MSGRAPH_TENANT_ID"),
    "client_id": environ.get("MSGRAPH_CLIENT_ID"),
    "client_secret": environ.get("MSGRAPH_CLIENT_SECRET"),
}
GRAPH_TARGET_PRODUCT = environ.get("MSGRAPH_TARGET_PRODUCT")
GRAPH_ACTION = "alert"
GRAPH_PASSIVE_ONLY = False
GRAPH_DAYS_TO_EXPIRE = (
    int(environ.get("MSGRAPH_DAYS_TO_EXPIRE")) if "MSGRAPH_DAYS_TO_EXPIRE" in environ else None
)
