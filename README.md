# MISP2Sentinel

A Python script that ingests alert telemetry from MISP and inserts it into Microsoft Sentinel via the Graph API.

It will use environment variables (see `dev.env` below) to connect to both.

## Usage

Example docker run:

```shell
# dev.env is the file as specified below which contains the configuration
% docker run --name=misp2sentinel -t --rm --env-file=dev.env --read-only --tmpfs=/data ghcr.io/hazcod/sentinel2misp/sentinel2misp:latest
```

## Build

With `make` and `docker` installed locally:

```shell
% make build
```

## Local development

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
