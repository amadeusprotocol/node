# syntax=docker/dockerfile:1
# podman build --tag erlang_builder -f build.Dockerfile

FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

ENV SSL_VERSION=3.6.4
ENV OTP_VERSION=OTP-29.0.6
ENV ELIXIR_VERSION=v1.20.4

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    build-essential \
    ca-certificates \
    clang-19 \
    cmake \
    curl \
    git \
    libncurses-dev \
    libxml2-utils \
    locales \
    m4 \
    mold \
    pkg-config \
    unixodbc-dev \
    xsltproc \
    zstd \
    && echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen \
    && locale-gen \
    && rm -rf /var/lib/apt/lists/*

ENV LANGUAGE=en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8
ENV LIBCLANG_PATH=/usr/lib/llvm-19/lib
ENV OPENSSL_ROOT_DIR=/opt/openssl

WORKDIR /root

RUN curl --fail --location --retry 3 --show-error --silent \
        "https://github.com/openssl/openssl/releases/download/openssl-$SSL_VERSION/openssl-$SSL_VERSION.tar.gz" \
        --output /tmp/openssl.tar.gz && \
    mkdir -p /tmp/openssl-src && \
    tar -xzf /tmp/openssl.tar.gz --strip-components=1 -C /tmp/openssl-src && \
    cd /tmp/openssl-src && \
    ./Configure \
        --prefix="$OPENSSL_ROOT_DIR" \
        --openssldir="$OPENSSL_ROOT_DIR/ssl" \
        --libdir=lib \
        enable-weak-ssl-ciphers \
        no-shared && \
    make -j"$(nproc)" && \
    make install_sw && \
    rm -rf /tmp/openssl-src /tmp/openssl.tar.gz

RUN mkdir -p /root/source && \
    git clone https://github.com/erlang/otp /root/source/otp && \
    cd /root/source/otp && \
    git checkout $OTP_VERSION
RUN cd /root/source/otp && \
    ./configure --with-ssl="$OPENSSL_ROOT_DIR" --disable-dynamic-ssl-lib --with-microstate-accounting=extra && make -j$(nproc) && make install

RUN mkdir -p /root/source && \
    git clone https://github.com/elixir-lang/elixir.git /root/source/elixir && \
    cd /root/source/elixir && \
    git checkout $ELIXIR_VERSION && \
    make clean && make install && \
    mix local.hex --force && mix local.rebar --force

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

CMD ["/bin/bash"]
