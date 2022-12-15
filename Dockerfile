FROM python:3.11-alpine

ENV PYTHONUNBUFFERED=1
ENV TMP_PACKAGES="gcc python3-dev musl-dev libffi-dev"

RUN addgroup -g 1000 syncuser \
    && adduser -u 1000 -D syncuser -s /bin/true -G syncuser \
    && mkdir -p /code/ \
    && apk add -U --no-cache $TMP_PACKAGES

WORKDIR /code/

COPY --chown=1000 /src/misp_to_sentinel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && apk del $TMP_PACKAGES

COPY --chown=1000 src/misp_to_sentinel/ .

ENV USER syncuser
ENV HOME /home/syncuser
USER 1000

ENTRYPOINT ["python"]
CMD ["main.py", "-v"]
