# Build from the repository root:  docker build -f deploy/Dockerfile -t lan-trap-receiver .
FROM python:3.13-slim

RUN useradd --system --uid 10514 --home-dir /data --shell /usr/sbin/nologin lantrap \
    && mkdir -p /data /config && chown lantrap:lantrap /data

WORKDIR /app
COPY lantrap /app/lantrap

USER lantrap
ENV PYTHONUNBUFFERED=1
EXPOSE 5514/udp 5514/tcp 6514/tcp
VOLUME ["/data"]

# The configuration is mounted read-only at /config; put the storage paths under /data.
ENTRYPOINT ["python", "-m", "lantrap", "--config", "/config/lantrap.toml"]
CMD ["run"]
