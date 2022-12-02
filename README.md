# MISP2Sentinel

A Python script that ingests alert telemetry from MISP and inserts it into Microsoft Sentinel via the Graph API.

It will use environment variables (see `dev.env` below) to connect to both.

## Build

With `make` and `docker` installed locally:

```shell
% make build
```

## Run

First create a local development file called `dev.env`:

```env
MISP_EVENT_LIMIT=1
MISP_BASE_URL=https://
MISP_KEY=

AZ_TENANT_ID=
AZ_MISP_CLIENT_ID=
AZ_MISP_CLIENT_SECRET=
AZ_SUBSCRIPTION=
AZ_SENTINEL_RG=
AZ_SENTINEL_WORKSPACE_NAME=
AZ_DAYS_TO_EXPIRE=
```

And now build & run the docker container:

```shell
% make
```
