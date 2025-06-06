# syntax=docker/dockerfile-upstream:experimental

FROM ubuntu:22.04 as build

RUN apt-get update -qq && apt-get install -y \
    git \
    cmake \
    g++ \
    pkg-config \
    libssl-dev \
    curl \
    llvm \
    clang \
    && rm -rf /var/lib/apt/lists/*

VOLUME [ /near ]
WORKDIR /near
COPY . .

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl https://sh.rustup.rs -sSf | \
    sh -s -- -y --no-modify-path --default-toolchain none

RUN rustup toolchain install

ENV PORTABLE=ON
ARG make_target=
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/tmp/target \
    make CARGO_TARGET_DIR=/tmp/target "${make_target:?make_target not set}" && \
    cp /tmp/target/release/neard /near/neard

# Docker image
FROM ubuntu:22.04

EXPOSE 3030 24567

RUN apt-get update -qq && apt-get install -y \
    libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/run_docker.sh /usr/local/bin/run.sh
COPY --from=build /near/neard /usr/local/bin/

CMD ["/usr/local/bin/run.sh"]
