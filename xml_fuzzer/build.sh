#!/bin/bash
# build.sh - Build libxml2/NSXMLParser fuzzer
# Handles both libFuzzer (local Xcode) and standalone harness (GitHub Actions CI)
set -e
cd "$(dirname "$0")"

# Find libxml2 headers
LIBXML2_INCLUDE=$(xcrun --show-sdk-path)/usr/include/libxml2
COMMON="-framework Foundation -framework CoreFoundation -lxml2 -I${LIBXML2_INCLUDE}"

echo "=== libxml2 / NSXMLParser Fuzzer ==="
echo ""

echo "[1/2] Creating seed corpus..."
mkdir -p corpus crashes

# Create XML seeds
cat > corpus/seed_xml_basic.bin << 'XMLEOF'
<?xml version="1.0"?>
<root attr="value"><child>text</child><empty/></root>
XMLEOF
printf '\x00' | cat - corpus/seed_xml_basic.bin > corpus/sax_basic.bin

cat > corpus/seed_xml_ns.bin << 'XMLEOF'
<?xml version="1.0"?>
<r:root xmlns:r="http://fuzz.local"><r:child>text</r:child></r:root>
XMLEOF
printf '\x01' | cat - corpus/seed_xml_ns.bin > corpus/dom_ns.bin

# XML plist
cat > /tmp/seed_xmlplist.bin << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>test</key><string>value</string></dict></plist>
XMLEOF
printf '\x02' | cat - /tmp/seed_xmlplist.bin > corpus/xmlplist.bin
rm -f /tmp/seed_xmlplist.bin

# HTML seed
printf '\x03' > corpus/html_basic.bin
echo '<html><head><title>Fuzz</title></head><body><p class="test">Hello</p></body></html>' >> corpus/html_basic.bin

# XPath seed (1-byte query length + query + XML)
printf '\x04\x05//root' > corpus/xpath_basic.bin
echo '<?xml version="1.0"?><root><a>1</a><b>2</b></root>' >> corpus/xpath_basic.bin

# DTD/entity seed
printf '\x05' > corpus/dtd_entity.bin
cat >> corpus/dtd_entity.bin << 'XMLEOF'
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test "expanded">]>
<root>&test;</root>
XMLEOF

echo "      Done. $(ls corpus/ | wc -l | tr -d ' ') seeds"

echo "[2/2] Building fuzzer..."
if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang -fsanitize=fuzzer -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with -fsanitize=fuzzer"
    clang $COMMON \
        -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_xml fuzz_xml.m 2>&1
else
    echo "      libFuzzer NOT available - building with standalone harness"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_xml.o fuzz_xml.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_xml fuzz_xml.o standalone_harness.o
    rm -f fuzz_xml.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Corpus seeds: $(ls corpus/ | wc -l | tr -d ' ') files"
echo "Run: ./fuzz_xml corpus/ -max_len=65536 -timeout=10 -artifact_prefix=crashes/"
