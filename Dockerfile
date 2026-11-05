# Runs the agent-canary listener (HTTP + DNS) and keeps alerts and state in /data.
#   docker run -d -p 8080:8080 -p 5300:5300/udp -v canary-data:/data IMAGE
# Other subcommands work too: docker run --rm IMAGE --help
FROM python:3.14.10-slim-trixie AS build

COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv venv /opt/venv \
    && uv pip install --python /opt/venv/bin/python --no-cache .

FROM python:3.14.10-slim-trixie

COPY --from=build /opt/venv /opt/venv
RUN adduser --disabled-password --gecos "" --uid 10001 canary \
    && mkdir -p /data/state \
    && chown -R canary /data

ENV PATH="/opt/venv/bin:$PATH" \
    AGENT_CANARY_HOME=/data/state
USER canary
VOLUME /data
EXPOSE 8080 5300/udp

ENTRYPOINT ["agent-canary"]
CMD ["listen", "--http", "0.0.0.0:8080", "--dns", "0.0.0.0:5300", "--log", "/data/alerts.jsonl"]
