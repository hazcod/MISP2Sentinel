
FROM alpine as intermediate

LABEL stage=intermediate

RUN apk update && \
    apk add --update git

RUN git clone https://github.com/nv-pipo/misp-to-sentinel-and-defender-connector.git

FROM python:3.7-alpine
ENV PYTHONUNBUFFERED=1

RUN apk update
RUN apk upgrade

RUN mkdir -p /code/
COPY --from=intermediate /misp-to-sentinel-and-defender-connector/app/src/ /code/misp_to_msgraph/
WORKDIR /code/misp_to_msgraph
RUN pip install pymisp==2.4.119.1
# Copy custom config file
ADD app/src/ /code/misp_to_msgraph/

RUN addgroup -g 1000 sync-user && \
    adduser -u 1000 -D sync-user -G sync-user
ENV USER sync-user
ENV HOME /home/sync-user
WORKDIR /home/sync-user
USER sync-user
