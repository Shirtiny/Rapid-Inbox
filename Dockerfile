FROM debian:trixie-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake make g++ libsqlite3-dev libssl-dev libunistring-dev libicu-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY cpp ./cpp
RUN sed -i 's/_72\b/_76/g; s/libicuuc\.so\.72/libicuuc.so.76/g' \
        cpp/ingestd/src/domain_matcher.cpp cpp/ingestd/CMakeLists.txt \
    && cmake -S cpp/ingestd -B cpp/ingestd/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build cpp/ingestd/build --target rapid-inbox-ingestd -j"$(nproc)"

FROM debian:trixie-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        libicu76 libsqlite3-0 libssl3 libunistring5 \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md sqlite_schema.sql ./
COPY app ./app
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir .
COPY --from=build /src/cpp/ingestd/build/rapid-inbox-ingestd /usr/local/bin/rapid-inbox-ingestd
ENV PATH=/opt/venv/bin:$PATH \
    STORAGE_ROOT=/data \
    DATABASE_PATH=/data/app.db \
    HOST=0.0.0.0 \
    PORT=20115 \
    SMTP_HOST=0.0.0.0 \
    SMTP_PORT=25
ENTRYPOINT ["/usr/bin/tini", "--"]
