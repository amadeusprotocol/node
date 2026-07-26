#!/bin/bash

#&& export ERL_COMPILER_OPTIONS=bin_opt_info \

CORES=$(nproc)
#-C codegen-units=$CORES
#&& export MAKEFLAGS='-j$CORES' \
podman run -it --rm -v ../.:/root/node --entrypoint bash erlang_builder -c "echo 'building amadeus..' \
    && cd /root/node/ex \
    && export MIX_ENV=prod \
    && export CC='clang-19' CXX='clang++-19' CFLAGS='-march=haswell -pipe' CXXFLAGS='-march=haswell -pipe' \
    && export RUSTFLAGS='-C target-cpu=haswell -C opt-level=3 -C link-arg=-fuse-ld=mold' \
    && export LLVM_CONFIG_PATH=/usr/bin/llvm-config-19 LIBCLANG_PATH=/usr/lib/llvm-19/lib \
    && export OPENSSL_ROOT_DIR=/root/openssl-3.6.2 \
    && export ERLANG_ROCKSDB_OPTS='-DOPENSSL_USE_STATIC_LIBS=TRUE -DWITH_LZ4=OFF -DWITH_SNAPPY=OFF -DWITH_BZ2=OFF -DWITH_ZLIB=OFF -DWITH_ZSTD=ON -DWITH_BUNDLE_ZSTD=ON' \
    && mix deps.get \
    && mix release \
    && cp _build/prod/rel/bakeware/ama amadeusd"
sha256sum amadeusd
./sign_release.sh
