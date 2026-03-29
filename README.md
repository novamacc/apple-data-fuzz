# apple-data-fuzz

Continuous fuzzing of Apple data serialization and parsing frameworks on macOS using libFuzzer with AddressSanitizer and UndefinedBehaviorSanitizer.

## Fuzzers

| Fuzzer | Target | Formats | Zero-Click Vectors |
|--------|--------|---------|-------------------|
| `unarchiver_fuzzer` | NSKeyedUnarchiver + NSPropertyList | Binary plist, XML plist, NSKeyedArchiver, JSON, NSAttributedString | iMessage (BlastDoor), XPC, Spotlight |
| `compression_fuzzer` | Compression.framework + QuickLook | LZFSE, LZ4, ZLIB, LZMA, ZIP central directory | IPA, IPSW, disk images, archives |
| `xml_fuzzer` | libxml2 + NSXMLParser | XML SAX/DOM, HTML, XPath, DTD/entity, XML plist | Property lists, SOAP, SVG, Office docs |
| `imagent_fuzzer` | imagent (iMessage daemon) | NSKeyedArchiver, NSAttributedString, binary plist, vCard, rich links | iMessage (some paths bypass BlastDoor) |

## CI

Runs on `macos-15` every 4 hours via GitHub Actions. Each fuzzer runs for ~5 hours with 3 parallel workers. Crash artifacts are uploaded automatically.

## Local Build

```bash
cd imagent_fuzzer && ./build.sh
./fuzz_imessage corpus/ -max_len=65536 -timeout=10 -jobs=4 -workers=4
```
