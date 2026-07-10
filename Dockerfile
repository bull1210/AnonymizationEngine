FROM python:3.11-slim AS builder
WORKDIR /app
COPY pyproject.toml README.md ./
COPY anonymizer/ anonymizer/
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.11-slim
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY --from=builder /app/dist/*.whl /tmp/
# [kafka] so the same image runs worker, serve, AND the scan-results bridge.
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[kafka]" && rm /tmp/*.whl
COPY config/ /etc/anonymizer/
ENV ANON_CONFIG=/etc/anonymizer/app.yaml
USER appuser
ENTRYPOINT ["anonymizer"]
CMD ["worker", "--config", "/etc/anonymizer/app.yaml"]
