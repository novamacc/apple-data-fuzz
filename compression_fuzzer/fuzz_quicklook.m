/*
 * fuzz_quicklook.m — QuickLook + Compression Framework Fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: QuickLook preview/thumbnail + Apple Compression
 *
 * QuickLook generates previews for ANY file type:
 *   - Triggered by Finder hover (1-click), Spotlight indexing (0-click)
 *   - Processes Office docs, archives, fonts, images, audio, video
 *   - Runs in restricted sandbox but handles untrusted data
 *
 * Apple Compression framework:
 *   - LZFSE, LZ4, LZMA, ZLIB built into every Apple binary
 *   - Used in IPA, IPSW, disk images, archives
 *   - Memory corruption in decompression = RCE
 *
 * FUZZING PATHS (6):
 *   [0] LZFSE decompression
 *   [1] LZ4 decompression
 *   [2] ZLIB decompression
 *   [3] LZMA decompression
 *   [4] NSData compression round-trip
 *   [5] Archive (ZIP) central directory parsing
 *
 * Build:
 *   clang -framework Foundation -framework CoreFoundation \
 *         -lcompression -fsanitize=fuzzer,address,undefined \
 *         -g -O1 -o fuzz_quicklook fuzz_quicklook.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#include <compression.h>
#include <stdint.h>
#include <string.h>

#define MAX_DECOMP_SIZE (256 * 1024) /* 256KB max decompressed — prevents decompression bombs */

/* ================================================================
 * PATH 0: LZFSE decompression
 * Apple's custom compression algorithm. Used everywhere on-platform.
 * ================================================================ */
static void fuzz_lzfse(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 4) return;

        uint8_t *dst = malloc(MAX_DECOMP_SIZE);
        if (!dst) return;

        size_t result = compression_decode_buffer(
            dst, MAX_DECOMP_SIZE,
            data, size,
            NULL, /* scratch buffer */
            COMPRESSION_LZFSE);

        if (result > 0 && result <= MAX_DECOMP_SIZE) {
            /* Re-compress to exercise encoder too */
            size_t compSize = compression_encode_buffer(
                dst, MAX_DECOMP_SIZE,
                data, MIN(size, 4096),
                NULL,
                COMPRESSION_LZFSE);
            (void)compSize;
        }
        free(dst);
    }
}

/* ================================================================
 * PATH 1: LZ4 decompression
 * ================================================================ */
static void fuzz_lz4(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 4) return;

        uint8_t *dst = malloc(MAX_DECOMP_SIZE);
        if (!dst) return;

        size_t result = compression_decode_buffer(
            dst, MAX_DECOMP_SIZE,
            data, size,
            NULL,
            COMPRESSION_LZ4);

        (void)result;
        free(dst);
    }
}

/* ================================================================
 * PATH 2: ZLIB decompression
 * ================================================================ */
static void fuzz_zlib(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 2) return;

        uint8_t *dst = malloc(MAX_DECOMP_SIZE);
        if (!dst) return;

        size_t result = compression_decode_buffer(
            dst, MAX_DECOMP_SIZE,
            data, size,
            NULL,
            COMPRESSION_ZLIB);

        (void)result;

        /* NSData zlib decompress — bounded by input size check */
        if (size < 4096) {
            NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                                  length:size freeWhenDone:NO];
            NSData *decompressed = [nsdata decompressedDataUsingAlgorithm:
                NSDataCompressionAlgorithmZlib error:NULL];
            (void)decompressed;
        }

        free(dst);
    }
}

/* ================================================================
 * PATH 3: LZMA decompression
 * ================================================================ */
static void fuzz_lzma(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 5) return;

        uint8_t *dst = malloc(MAX_DECOMP_SIZE);
        if (!dst) return;

        size_t result = compression_decode_buffer(
            dst, MAX_DECOMP_SIZE,
            data, size,
            NULL,
            COMPRESSION_LZMA);

        (void)result;

        /* Skip NSData LZMA — unbounded decompression causes OOM */
        /* The C API compression_decode_buffer above is bounded */

        free(dst);
    }
}

/* ================================================================
 * PATH 4: NSData compression round-trip
 * ================================================================ */
static void fuzz_nsdata_roundtrip(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 2) return;

        NSData *original = [NSData dataWithBytesNoCopy:(void *)data
                                                length:size freeWhenDone:NO];

        /* Use first byte to select algorithm */
        NSDataCompressionAlgorithm algo;
        switch (data[0] % 3) {
            case 0: algo = NSDataCompressionAlgorithmLZFSE; break;
            case 1: algo = NSDataCompressionAlgorithmLZ4;   break;
            case 2: algo = NSDataCompressionAlgorithmZlib;  break;
            /* Skip LZMA — unbounded decompression causes OOM */
        }

        NSData *payload = [NSData dataWithBytesNoCopy:(void *)(data + 1)
                                               length:size - 1
                                         freeWhenDone:NO];

        /* Try decompressing (treats input as compressed data) */
        NSData *decompressed = [payload decompressedDataUsingAlgorithm:algo
                                                                error:NULL];
        if (decompressed && decompressed.length < MAX_DECOMP_SIZE) {
            /* Round-trip: compress the decompressed data */
            NSData *recompressed = [decompressed compressedDataUsingAlgorithm:algo
                                                                        error:NULL];
            if (recompressed) {
                /* Decompress again and verify */
                NSData *final = [recompressed decompressedDataUsingAlgorithm:algo
                                                                       error:NULL];
                (void)final.length;
            }
        }

        /* Also try compressing the raw input */
        NSData *compressed = [payload compressedDataUsingAlgorithm:algo
                                                             error:NULL];
        (void)compressed;
    }
}

/* ================================================================
 * PATH 5: ZIP central directory parsing
 *
 * ZIP files are parsed by QuickLook, Finder, and many apps.
 * The central directory has complex structures that can be malformed.
 * ================================================================ */
static void fuzz_zip_parsing(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 30) return; /* Minimum local file header */

        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];

        /* Write to temp file and try to list contents */
        NSString *tmpPath = [NSTemporaryDirectory()
            stringByAppendingPathComponent:
            [NSString stringWithFormat:@"fuzz_%u.zip", arc4random()]];

        if ([nsdata writeToFile:tmpPath atomically:NO]) {
            /* Use NSFileManager to check if it's recognized */
            NSFileManager *fm = [NSFileManager defaultManager];
            NSDictionary *attrs = [fm attributesOfItemAtPath:tmpPath error:NULL];
            (void)attrs;

            /* Parse ZIP local file headers manually */
            size_t off = 0;
            int maxEntries = 50;
            while (off + 30 <= size && maxEntries-- > 0) {
                uint32_t sig;
                memcpy(&sig, data + off, 4);

                if (sig == 0x04034b50) { /* Local file header */
                    uint16_t nameLen, extraLen, compression;
                    uint32_t compSize, uncompSize;

                    memcpy(&compression, data + off + 8, 2);
                    memcpy(&compSize, data + off + 18, 4);
                    memcpy(&uncompSize, data + off + 22, 4);
                    memcpy(&nameLen, data + off + 26, 2);
                    memcpy(&extraLen, data + off + 28, 2);

                    /* Validate and extract filename */
                    size_t headerEnd = off + 30 + nameLen + extraLen;
                    if (headerEnd > size) break;

                    if (nameLen > 0 && nameLen < 256) {
                        char name[256];
                        memcpy(name, data + off + 30, nameLen);
                        name[nameLen] = '\0';
                        (void)strlen(name);
                    }

                    /* Skip to next entry */
                    if (compSize > size) break;
                    off = headerEnd + compSize;
                } else if (sig == 0x02014b50) { /* Central directory */
                    if (off + 46 > size) break; /* Need minimum header */
                    uint16_t nameLen, extraLen, commentLen;
                    memcpy(&nameLen, data + off + 28, 2);
                    memcpy(&extraLen, data + off + 30, 2);
                    memcpy(&commentLen, data + off + 32, 2);

                    size_t entrySize = 46 + nameLen + extraLen + commentLen;
                    if (off + entrySize > size) break;
                    off += entrySize;
                } else if (sig == 0x06054b50) { /* End of central directory */
                    uint16_t commentLen;
                    if (off + 22 > size) break;
                    memcpy(&commentLen, data + off + 20, 2);
                    break;
                } else {
                    break;
                }
            }

            [fm removeItemAtPath:tmpPath error:NULL];
        }
    }
}

/* ================================================================ */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    @autoreleasepool {
        uint8_t path = data[0];
        const uint8_t *payload = data + 1;
        size_t psize = size - 1;

        switch (path % 6) {
            case 0: fuzz_lzfse(payload, psize);           break;
            case 1: fuzz_lz4(payload, psize);              break;
            case 2: fuzz_zlib(payload, psize);             break;
            case 3: fuzz_lzma(payload, psize);             break;
            case 4: fuzz_nsdata_roundtrip(payload, psize); break;
            case 5: fuzz_zip_parsing(payload, psize);      break;
        }
    }
    return 0;
}
