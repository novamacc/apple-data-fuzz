#!/bin/bash
# build.sh - Build the iMessage/imagent Protocol Fuzzer suite
# Handles both libFuzzer (local Xcode) and standalone harness (GitHub Actions CI)
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

COMMON="-framework Foundation -framework CoreFoundation -framework Contacts"

echo "=== iMessage Zero-Click Protocol Fuzzer ==="
echo ""

echo "[1/3] Building seed generator..."
clang $COMMON -O2 -o seed_generator seed_generator.m 2>&1
echo "      Done."

echo "[2/3] Generating seed corpus..."
mkdir -p corpus crashes
./seed_generator corpus/
echo ""

echo "[3/3] Building fuzzer..."
if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang -fsanitize=fuzzer -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with -fsanitize=fuzzer"
    clang $COMMON \
        -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_imessage fuzz_imessage.m 2>&1
else
    echo "      libFuzzer NOT available - building with standalone harness"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_imessage.o fuzz_imessage.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_imessage fuzz_imessage.o standalone_harness.o
    rm -f fuzz_imessage.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
SEED_COUNT=$(ls corpus/ | wc -l | tr -d ' ')
echo "Corpus seeds: $SEED_COUNT files"
echo ""
echo "Run commands:"
echo "  Quick (60s):     ./fuzz_imessage corpus/ -max_len=65536 -timeout=10 -max_total_time=60"
echo "  Parallel:        ./fuzz_imessage corpus/ -max_len=65536 -timeout=10 -jobs=4 -workers=4"
echo "  Overnight:       ./fuzz_imessage corpus/ -max_len=65536 -timeout=10 -jobs=8 -workers=4 -artifact_prefix=crashes/"
echo ""

if [ "$1" = "fuzz" ]; then
    echo "=== Starting 60-second fuzzing run ==="
    ./fuzz_imessage corpus/ -max_len=65536 -timeout=10 -max_total_time=60 \
        -print_final_stats=1 -artifact_prefix=crashes/
fi
