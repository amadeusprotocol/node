#!/bin/bash
set -e
cd "$(dirname "$0")"
cargo +nightly build --release --examples --target riscv64im-zba-zbb-none.json -Zbuild-std=core,alloc -Zjson-target-spec
mkdir -p out
for f in examples/*.rs; do
    name=$(basename "$f" .rs)
    cp "target/riscv64im-zba-zbb-none/release/examples/$name" "out/$name.elf"
done
fixtures=../../ex/native/rdb/src/consensus/tests/fixtures/riscv
if [ -d "$fixtures" ]; then
    cp out/*.elf "$fixtures/"
fi
ls -la out
