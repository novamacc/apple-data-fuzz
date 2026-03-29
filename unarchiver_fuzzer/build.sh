#!/bin/bash
# build.sh - Build NSKeyedUnarchiver/plist fuzzer
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework CoreFoundation"

echo "=== NSKeyedUnarchiver + Plist Fuzzer ==="
echo ""

echo "[1/2] Creating seed corpus..."
mkdir -p corpus crashes

# Generate seeds inline
cat > /tmp/gen_unarchiver_seeds.m << 'SEEDEOF'
#import <Foundation/Foundation.h>
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
        // Binary plist seed
        NSDictionary *d = @{@"key": @"value", @"num": @42, @"data": [@"test" dataUsingEncoding:NSUTF8StringEncoding]};
        NSData *bp = [NSPropertyListSerialization dataWithPropertyList:d format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
        if (bp) ws(dir, "bplist.bin", 0, bp);
        // XML plist seed
        NSData *xp = [NSPropertyListSerialization dataWithPropertyList:d format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
        if (xp) ws(dir, "xmlplist.bin", 1, xp);
        // NSKeyedArchiver seeds
        NSData *ka = [NSKeyedArchiver archivedDataWithRootObject:d requiringSecureCoding:NO error:nil];
        if (ka) { ws(dir, "keyed_secure.bin", 2, ka); ws(dir, "keyed_insecure.bin", 3, ka); }
        // JSON seed
        NSData *js = [NSJSONSerialization dataWithJSONObject:d options:0 error:nil];
        if (js) ws(dir, "json.bin", 4, js);
        // Attributed string seed
        NSAttributedString *as = [[NSAttributedString alloc] initWithString:@"Hello World"];
        NSData *asd = [NSKeyedArchiver archivedDataWithRootObject:as requiringSecureCoding:NO error:nil];
        if (asd) ws(dir, "attrstring.bin", 5, asd);
        printf("[+] Unarchiver seeds generated\n");
        return 0;
    }
}
SEEDEOF
clang -framework Foundation -O2 -o /tmp/gen_una_seeds /tmp/gen_unarchiver_seeds.m 2>&1
/tmp/gen_una_seeds corpus/
rm -f /tmp/gen_una_seeds /tmp/gen_unarchiver_seeds.m
echo "      Done."

echo "[2/2] Building fuzzer (ASAN + UBSan + libFuzzer)..."
clang $COMMON \
    -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=undefined \
    -g -O1 \
    -o fuzz_unarchiver fuzz_unarchiver.m 2>&1
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Corpus seeds: $(ls corpus/ | wc -l | tr -d ' ') files"
echo "Run: ./fuzz_unarchiver corpus/ -max_len=65536 -timeout=10 -artifact_prefix=crashes/"
