#!/bin/bash
# build.sh - Build Compression/QuickLook fuzzer
# Handles both libFuzzer (local Xcode) and standalone harness (GitHub Actions CI)
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework CoreFoundation -lcompression"

echo "=== Compression + QuickLook Fuzzer ==="
echo ""

echo "[1/2] Creating seed corpus..."
mkdir -p corpus crashes

# Generate compressed seeds inline
cat > /tmp/gen_comp_seeds.m << 'SEEDEOF'
#import <Foundation/Foundation.h>
#include <compression.h>
#include <sys/stat.h>
static void ws(const char *d, const char *n, uint8_t p, NSData *data) {
    NSMutableData *f = [NSMutableData dataWithBytes:&p length:1];
    [f appendData:data];
    NSString *path = [NSString stringWithFormat:@"%s/%s", d, n];
    [f writeToFile:path atomically:YES];
    printf("  [+] %s (%lu bytes)\n", n, (unsigned long)f.length);
}
int main(int argc, char *argv[]) {
    @autoreleasepool {
        const char *dir = argc > 1 ? argv[1] : "corpus";
        mkdir(dir, 0755);
        NSData *raw = [@"The quick brown fox jumps over the lazy dog. Repeated data for compression." dataUsingEncoding:NSUTF8StringEncoding];
        // LZFSE
        NSData *lzfse = [raw compressedDataUsingAlgorithm:NSDataCompressionAlgorithmLZFSE error:nil];
        if (lzfse) ws(dir, "lzfse.bin", 0, lzfse);
        // LZ4
        NSData *lz4 = [raw compressedDataUsingAlgorithm:NSDataCompressionAlgorithmLZ4 error:nil];
        if (lz4) ws(dir, "lz4.bin", 1, lz4);
        // Zlib
        NSData *zlib = [raw compressedDataUsingAlgorithm:NSDataCompressionAlgorithmZlib error:nil];
        if (zlib) ws(dir, "zlib.bin", 2, zlib);
        // LZMA
        NSData *lzma = [raw compressedDataUsingAlgorithm:NSDataCompressionAlgorithmLZMA error:nil];
        if (lzma) ws(dir, "lzma.bin", 3, lzma);
        // NSData roundtrip seed
        if (zlib) ws(dir, "roundtrip.bin", 4, zlib);
        // Minimal ZIP
        uint8_t zip[] = {
            0x50,0x4B,0x03,0x04, 0x14,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x05,0x00,0x00,0x00,'t','e','s','t','.', 'H','e','l','l','o',
            0x50,0x4B,0x01,0x02, 0x14,0x03,0x14,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
            0x05,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0xA4,0x81,0x00,0x00,0x00,0x00,'t','e','s','t','.',
            0x50,0x4B,0x05,0x06, 0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,
            0x33,0x00,0x00,0x00, 0x24,0x00,0x00,0x00,0x00,0x00
        };
        ws(dir, "minimal.zip", 5, [NSData dataWithBytes:zip length:sizeof(zip)]);
        printf("[+] Compression seeds generated\n");
        return 0;
    }
}
SEEDEOF
clang -framework Foundation -lcompression -O2 -o /tmp/gen_comp_seeds /tmp/gen_comp_seeds.m 2>&1
/tmp/gen_comp_seeds corpus/
rm -f /tmp/gen_comp_seeds /tmp/gen_comp_seeds.m
echo "      Done."

echo "[2/2] Building fuzzer..."
if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang  -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with "
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_quicklook fuzz_quicklook.m 2>&1
else
    echo "      libFuzzer NOT available - building with standalone harness"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_quicklook.o fuzz_quicklook.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_quicklook fuzz_quicklook.o standalone_harness.o
    rm -f fuzz_quicklook.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Corpus seeds: $(ls corpus/ | wc -l | tr -d ' ') files"
echo "Run: ./fuzz_quicklook corpus/ -max_len=65536 -timeout=10 -artifact_prefix=crashes/"
