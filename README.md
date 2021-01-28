# About
This project contains a connector to push MISP IOCs to Azure Sentinel and Microsoft Defender ATP. An alternative to https://github.com/microsoftgraph/security-api-solutions/tree/master/Samples/MISP

# Installation
## Requirements
### Credentials
- Credentials to connect to MISP server
- Credentials to connect to MS Graph. See https://techcommunity.microsoft.com/t5/azure-sentinel/integrating-open-source-threat-feeds-with-misp-and-sentinel/ba-p/1350371 on how to create the app registry and add the permissions to push the TI via MS Graph.
### Python environment
Install dependencies on a python 3.8+ environment (probably works with older versions of python, but it has not been tested).
~~~shell
pip install pymisp
~~~

## Download
~~~shell
git clone git@github.com:nv-pipo/misp-to-sentinel-and-defender-connector.git
~~~

# Running
Recommended use is to have a cronjob and run the script every hour.

If you are planning to run on Kubernetes, you can store the credentials on k8s secrets and provided to the pod via env variables.

If you are using Azure Functions, the function can be called by a playbook retrieving the credentials from a key vault.
~~~shell
# Either hard code authentication credentials on config.py or use env variables. 
export MISP_KEY="MISP auth token"
export MISP_BASE_URL="https://mispurl"

export MSGRAPH_TENANT_ID="TENANT ID"
export MSGRAPH_CLIENT_ID="MS GRAPH CLIENT ID"
export MSGRAPH_CLIENT_SECRET="MS GRAPH CLIENT TOKEN"
export MSGRAPH_TARGET_PRODUCT="Target product" # Either 'Azure Sentinel' or 'Microsoft Defender ATP'
export MSGRAPH_DAYS_TO_EXPIRE="20" # number of days after which the IOC will expire

# run
python ${DOWNLOAD_FOLDER}/misp-to-sentinel-and-defender-connector/app/src/main.py
~~~

# References
- [MS Graph TI references](https://docs.microsoft.com/en-us/graph/api/resources/tiindicator)
- [PyMISP reference](https://pymisp.readthedocs.io/en/latest/modules.html)
