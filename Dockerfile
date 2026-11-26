FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && install -d -o 10001 -g 10001 -m 0755 /app/cert

FROM base AS tester
COPY client_tests.py file_test_fixture.py ./
USER 10001:10001
CMD ["python", "client_tests.py"]

FROM base AS server
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --only-binary=:all: -r requirements.txt \
    && install -d -o 10001 -g 10001 -m 0700 /app/data /app/keys /app/tls
COPY server.py audit_storage.py file_test_fixture.py ./
USER 10001:10001
EXPOSE 8443
CMD ["python", "server.py"]
