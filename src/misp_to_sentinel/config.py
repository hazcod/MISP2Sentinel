import os

graph_auth = {
    'tenant': os.environ.get('AZ_TENANT_ID'),
    'client_id': os.environ.get('AZ_MISP_CLIENT_ID'),
    'client_secret': os.environ.get('AZ_MISP_CLIENT_SECRET'),
}
targetProduct = 'Azure Sentinel'
misp_event_filters = {
    'org': '',
    'category': '',
    'timestamp': '30d',
}
action = 'alert'
passiveOnly = False
days_to_expire = int(os.environ.get('AZ_DAYS_TO_EXPIRE'))
misp_key = os.environ.get('MISP_KEY')
misp_domain = os.environ.get('MISP_BASE_URL')
misp_verifycert = True
