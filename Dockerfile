FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system proxy-traffic \
    && useradd --system --gid proxy-traffic --home-dir /app proxy-traffic

WORKDIR /app

COPY server/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY server/server.py collector/collector.py /app/
COPY docker/entrypoint.sh /usr/local/bin/proxy-traffic-entrypoint

RUN chmod 0755 /usr/local/bin/proxy-traffic-entrypoint \
    && mkdir -p /var/lib/proxy-traffic /etc/proxy-traffic \
    && chown -R proxy-traffic:proxy-traffic /app /var/lib/proxy-traffic /etc/proxy-traffic

USER proxy-traffic
EXPOSE 9460

ENTRYPOINT ["/usr/local/bin/proxy-traffic-entrypoint"]
