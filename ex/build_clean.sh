#!/bin/bash

CORES=$(nproc)
#-C codegen-units=$CORES
#&& export MAKEFLAGS='-j$CORES' \
podman run -it --rm -v ../.:/root/node --entrypoint bash erlang_builder -c "echo 'building amadeus..' \
    && cd /tmp \
    && git clone https://github.com/amadeusprotocol/node \
    && cd /tmp/node/ex \
    && export MIX_ENV=prod \
    && export CC='clang-19' CXX='clang++-19' CFLAGS='-march=haswell -pipe' CXXFLAGS='-march=haswell -pipe' \
    && export RUSTFLAGS='-C target-cpu=haswell -C opt-level=3 -C link-arg=-fuse-ld=mold' \
    && export LLVM_CONFIG_PATH=/usr/bin/llvm-config-19 LIBCLANG_PATH=/usr/lib/llvm-19/lib \
    && mix deps.get \
    && mix release \
    && cp _build/prod/rel/bakeware/ama /root/node/ex/amadeusd"
sha256sum amadeusd
./sign_release.sh
