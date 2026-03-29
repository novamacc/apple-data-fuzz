/*
 * fuzz_unarchiver.m — NSKeyedUnarchiver + NSPropertyList Fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: NSKeyedUnarchiver + NSPropertyListSerialization
 *
 * WHY THIS IS CRITICAL:
 *   - FORCEDENTRY's exploit chain used NSKeyedUnarchiver gadgets
 *   - BlastDoor deserializes iMessage payloads via NSKeyedUnarchiver
 *   - Property lists are parsed EVERYWHERE on Apple platforms
 *   - XPC messages use bplist encoding internally
 *   - Spotlight indexes plist metadata from any file
 *   - Info.plist, entitlements, preferences — all plist
 *
 * FUZZING PATHS (6):
 *   [0] Binary plist parsing (bplist00/bplist15/bplist16/bplist17)
 *   [1] XML plist parsing
 *   [2] NSKeyedUnarchiver (secure coding ON)
 *   [3] NSKeyedUnarchiver (secure coding OFF — legacy apps)
 *   [4] JSON parsing (NSJSONSerialization)
 *   [5] Attributed string from plist data
 *
 * Build:
 *   clang -framework Foundation -framework CoreFoundation \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_unarchiver fuzz_unarchiver.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#include <stdint.h>

/* ================================================================
 * PATH 0: Binary plist (bplist) parsing
 *
 * Binary plists are the native serialization format.
 * Multiple versions: bplist00 (original), bplist15/16/17 (newer).
 * ================================================================ */
static void fuzz_bplist(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];
        NSError *error = nil;

        /* Parse as property list */
        id plist = [NSPropertyListSerialization
            propertyListWithData:nsdata
            options:NSPropertyListImmutable
            format:NULL
            error:&error];

        if (plist) {
            /* Walk the parsed plist to exercise all types */
            if ([plist isKindOfClass:[NSDictionary class]]) {
                NSDictionary *dict = (NSDictionary *)plist;
                for (NSString *key in dict) {
                    id val = dict[key];
                    if ([val isKindOfClass:[NSData class]])
                        (void)[(NSData *)val length];
                    else if ([val isKindOfClass:[NSString class]])
                        (void)[(NSString *)val length];
                    else if ([val isKindOfClass:[NSNumber class]])
                        (void)[(NSNumber *)val integerValue];
                    else if ([val isKindOfClass:[NSArray class]])
                        (void)[(NSArray *)val count];
                    else if ([val isKindOfClass:[NSDate class]])
                        (void)[(NSDate *)val timeIntervalSince1970];
                }
            } else if ([plist isKindOfClass:[NSArray class]]) {
                NSArray *arr = (NSArray *)plist;
                for (id item in arr) {
                    (void)[item description];
                }
            }

            /* Round-trip: serialize back */
            NSData *reserial = [NSPropertyListSerialization
                dataWithPropertyList:plist
                format:NSPropertyListBinaryFormat_v1_0
                options:0
                error:NULL];
            (void)reserial;
        }
    }
}

/* ================================================================
 * PATH 1: XML plist parsing
 * ================================================================ */
static void fuzz_xml_plist(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];

        id plist = [NSPropertyListSerialization
            propertyListWithData:nsdata
            options:NSPropertyListMutableContainersAndLeaves
            format:NULL
            error:NULL];

        if (plist) {
            /* Mutate if mutable (exercises different code paths) */
            if ([plist isKindOfClass:[NSMutableDictionary class]]) {
                NSMutableDictionary *dict = (NSMutableDictionary *)plist;
                dict[@"fuzz_key"] = @"fuzz_value";
                [dict removeObjectForKey:@"fuzz_key"];
            }

            /* Re-serialize as XML */
            NSData *xml = [NSPropertyListSerialization
                dataWithPropertyList:plist
                format:NSPropertyListXMLFormat_v1_0
                options:0
                error:NULL];
            if (xml) {
                /* Parse the XML output again */
                (void)[NSPropertyListSerialization
                    propertyListWithData:xml
                    options:NSPropertyListImmutable
                    format:NULL
                    error:NULL];
            }
        }
    }
}

/* ================================================================
 * PATH 2: NSKeyedUnarchiver (secure coding)
 *
 * This is the BlastDoor code path. Secure coding validates
 * class types during deserialization.
 * ================================================================ */
static void fuzz_keyed_secure(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];

        @try {
            NSSet *allowed = [NSSet setWithArray:@[
                [NSDictionary class],
                [NSArray class],
                [NSString class],
                [NSNumber class],
                [NSData class],
                [NSDate class],
                [NSURL class],
                [NSNull class],
                [NSSet class],
                [NSOrderedSet class],
                [NSValue class],
            ]];

            NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc]
                initForReadingFromData:nsdata error:NULL];
            if (unarchiver) {
                unarchiver.requiresSecureCoding = YES;

                id obj = [unarchiver decodeObjectOfClasses:allowed
                                                    forKey:NSKeyedArchiveRootObjectKey];
                if (obj) {
                    if ([obj isKindOfClass:[NSDictionary class]]) {
                        NSDictionary *d = (NSDictionary *)obj;
                        (void)d.count;
                        (void)d.allKeys;
                    } else if ([obj isKindOfClass:[NSArray class]]) {
                        NSArray *a = (NSArray *)obj;
                        (void)a.count;
                    }
                }
                [unarchiver finishDecoding];
            }
        } @catch (NSException *e) {
            /* Exceptions are expected for malformed archives */
        }
    }
}

/* ================================================================
 * PATH 3: NSKeyedUnarchiver (insecure — legacy apps)
 *
 * Many apps still use unarchiveObjectWithData: which doesn't
 * validate classes. This is where gadget chains work.
 * ================================================================ */
static void fuzz_keyed_insecure(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];

        @try {
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Wdeprecated-declarations"
            id obj = [NSKeyedUnarchiver unarchiveObjectWithData:nsdata];
            #pragma clang diagnostic pop

            if (obj) {
                (void)[obj description];

                /* If it's an attributed string, exercise it */
                if ([obj isKindOfClass:[NSAttributedString class]]) {
                    NSAttributedString *as = (NSAttributedString *)obj;
                    (void)as.length;
                    (void)as.string;
                    if (as.length > 0 && as.length < 10000) {
                        NSDictionary *attrs = [as attributesAtIndex:0
                            effectiveRange:NULL];
                        (void)attrs.count;
                    }
                }
            }
        } @catch (NSException *e) {
            /* Expected */
        }
    }
}

/* ================================================================
 * PATH 4: JSON parsing
 * ================================================================ */
static void fuzz_json(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];

        id json = [NSJSONSerialization JSONObjectWithData:nsdata
            options:NSJSONReadingMutableContainers |
                    NSJSONReadingMutableLeaves |
                    NSJSONReadingFragmentsAllowed
            error:NULL];

        if (json) {
            /* Serialize back */
            if ([NSJSONSerialization isValidJSONObject:json]) {
                NSData *output = [NSJSONSerialization dataWithJSONObject:json
                    options:NSJSONWritingSortedKeys
                    error:NULL];
                (void)output.length;
            }

            /* Walk structure */
            if ([json isKindOfClass:[NSDictionary class]]) {
                for (id key in (NSDictionary *)json) {
                    (void)[(NSDictionary *)json objectForKey:key];
                }
            } else if ([json isKindOfClass:[NSArray class]]) {
                for (id item in (NSArray *)json) {
                    (void)[item description];
                }
            }
        }
    }
}

/* ================================================================
 * PATH 5: NSAttributedString from plist (iMessage rich text)
 *
 * iMessage sends rich text as archived NSAttributedString.
 * This exercises the full deserialization + text layout pipeline.
 * ================================================================ */
static void fuzz_attributed_plist(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];

        @try {
            /* Try as archived attributed string */
            NSKeyedUnarchiver *una = [[NSKeyedUnarchiver alloc]
                initForReadingFromData:nsdata error:NULL];
            if (una) {
                una.requiresSecureCoding = NO;
                NSAttributedString *as = [una decodeObjectOfClass:
                    [NSAttributedString class]
                    forKey:NSKeyedArchiveRootObjectKey];
                if (as && as.length > 0 && as.length < 50000) {
                    (void)as.string;
                    /* Enumerate all attributes */
                    [as enumerateAttributesInRange:NSMakeRange(0, MIN(as.length, 1000))
                        options:0
                        usingBlock:^(NSDictionary *attrs, NSRange range, BOOL *stop) {
                            (void)attrs.count;
                        }];
                }
                [una finishDecoding];
            }
        } @catch (NSException *e) {
            /* Expected */
        }

        /* Also try as raw plist → attributed string init */
        @try {
            NSDictionary *dict = [NSPropertyListSerialization
                propertyListWithData:nsdata
                options:NSPropertyListImmutable
                format:NULL
                error:NULL];
            if ([dict isKindOfClass:[NSDictionary class]]) {
                NSString *text = dict[@"string"];
                if ([text isKindOfClass:[NSString class]] && text.length < 10000) {
                    NSAttributedString *as = [[NSAttributedString alloc]
                        initWithString:text];
                    (void)as.length;
                }
            }
        } @catch (NSException *e) {
            /* Expected */
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
            case 0: fuzz_bplist(payload, psize);          break;
            case 1: fuzz_xml_plist(payload, psize);       break;
            case 2: fuzz_keyed_secure(payload, psize);    break;
            case 3: fuzz_keyed_insecure(payload, psize);  break;
            case 4: fuzz_json(payload, psize);             break;
            case 5: fuzz_attributed_plist(payload, psize); break;
        }
    }
    return 0;
}
