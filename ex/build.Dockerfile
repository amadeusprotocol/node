# syntax=docker/dockerfile:1
# podman build --tag erlang_builder -f build.Dockerfile

FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

ENV SSL_VERSION=3.6.4
ENV OTP_VERSION=OTP-29.0.6
ENV ELIXIR_VERSION=v1.20.4

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf m4 cmake pkg-config clang-19 mold \
        libncurses-dev unixodbc-dev xsltproc libxml2-utils \
        ca-certificates curl git locales zstd \
    && echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && locale-gen \
    && rm -rf /var/lib/apt/lists/*

ENV LANGUAGE=en_US.UTF-8 LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
ENV LIBCLANG_PATH=/usr/lib/llvm-19/lib
ENV OPENSSL_ROOT_DIR=/opt/openssl

WORKDIR /root

RUN mkdir -p /tmp/openssl-src && cd /tmp/openssl-src \
    && curl -fsSL --retry 3 "https://github.com/openssl/openssl/releases/download/openssl-$SSL_VERSION/openssl-$SSL_VERSION.tar.gz" \
        | tar -xz --strip-components=1 \
    && ./Configure --prefix="$OPENSSL_ROOT_DIR" --openssldir="$OPENSSL_ROOT_DIR/ssl" --libdir=lib enable-weak-ssl-ciphers no-shared \
    && make -j"$(nproc)" && make install_sw \
    && cd / && rm -rf /tmp/openssl-src

RUN git clone --depth 1 --branch $OTP_VERSION https://github.com/erlang/otp /root/source/otp \
    && cd /root/source/otp \
    && ./configure --with-ssl="$OPENSSL_ROOT_DIR" --disable-dynamic-ssl-lib --with-microstate-accounting=extra \
    && make -j"$(nproc)" && make install

RUN git clone --depth 1 --branch $ELIXIR_VERSION https://github.com/elixir-lang/elixir.git /root/source/elixir \
    && cd /root/source/elixir && make install \
    && mix local.hex --force && mix local.rebar --force

RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

CMD ["/bin/bash"]
