FROM python:3.11-alpine

ENV PYTHONUNBUFFERED=1

RUN addgroup -g 1000 syncuser \
    && adduser -u 1000 -D syncuser -s /bin/true -G syncuser \
    && apk update && apk upgrade \
    && mkdir -p /code/

WORKDIR /code/

COPY --chown=1000 /src/misp_to_sentinel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=1000 src/misp_to_sentinel/ .

ENV USER syncuser
ENV HOME /home/syncuser
USER 1000

ENTRYPOINT ["python"]
CMD ["main.py"]
