FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system proxy-hub \
    && useradd --system --gid proxy-hub --home-dir /app proxy-hub

WORKDIR /app

COPY server/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY server/server.py collector/collector.py /app/
COPY docker/entrypoint.sh /usr/local/bin/proxy-hub-entrypoint

RUN chmod 0755 /usr/local/bin/proxy-hub-entrypoint \
    && mkdir -p /var/lib/proxy-hub /etc/proxy-hub \
    && chown -R proxy-hub:proxy-hub /app /var/lib/proxy-hub /etc/proxy-hub

USER proxy-hub
EXPOSE 9460

ENTRYPOINT ["/usr/local/bin/proxy-hub-entrypoint"]
