'''Config variables script.'''
from os import environ
from datetime import datetime, timedelta

# TODO: this logic should be run only once or not be in the configfile
end = datetime.now().replace(minute=0, second=0, microsecond=0)
start = end - timedelta(days=1)
start_ts = int(datetime.timestamp(start))
end_ts = int(datetime.timestamp(end))

MISP_EVENT_FILTERS = {
    'timestamp': [start_ts, end_ts],
    'published': True
}
MISP_KEY = environ.get('MISP_KEY')
MISP_DOMAIN = environ.get('MISP_BASE_URL')
MISP_VERIFYCERT = False

GRAPH_AUTH = {
    'tenant': environ.get('MSGRAPH_TENANT_ID'),
    'client_id': environ.get('MSGRAPH_CLIENT_ID'),
    'client_secret': environ.get('MSGRAPH_CLIENT_SECRET')
}
TARGET_PRODUCT = environ.get('MSGRAPH_TARGET_PRODUCT')
ACTION = 'alert'
PASSIVE_ONLY = False
DAYS_TO_EXPIRE = int(environ.get('MSGRAPH_DAYS_TO_EXPIRE'))
