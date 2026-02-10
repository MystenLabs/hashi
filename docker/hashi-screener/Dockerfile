FROM rust:slim-bullseye AS builder
ARG PROFILE=release
ARG GIT_REVISION
ENV GIT_REVISION=$GIT_REVISION
WORKDIR /app

RUN apt-get update && apt-get install -y cmake clang libssl-dev pkg-config protobuf-compiler

COPY Cargo.toml Cargo.lock ./
COPY crates crates

RUN cargo build --profile ${PROFILE} --bin hashi-screener

FROM debian:bullseye-slim AS runtime
RUN apt-get update && apt-get install -y libjemalloc-dev ca-certificates curl && rm -rf /var/lib/apt/lists/*
ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so
WORKDIR /app

COPY --from=builder /app/target/release/hashi-screener /usr/local/bin

ARG BUILD_DATE
ARG GIT_REVISION
LABEL build-date=$BUILD_DATE
LABEL git-revision=$GIT_REVISION

EXPOSE 50051
EXPOSE 9184

CMD ["hashi-screener"]
