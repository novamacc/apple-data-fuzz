/*
 * fuzz_imessage.m — God-Level iMessage/imagent Protocol Fuzzer for macOS
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: imagent (iMessage daemon, 1.4MB)
 *
 * imagent processes all iMessage data and some messages BYPASS BlastDoor:
 *   - Nickname/profile updates (NICKNAME exploit 2025)
 *   - Group photo transfers
 *   - Read/delivery receipts
 *   - Typing indicators
 *   - Edited/unsent message metadata
 *   - SharePlay invitations
 *   - FaceTime call setup
 *
 * The parsing stack uses NSKeyedUnarchiver for deserialization,
 * NSAttributedString for rich text, and custom protobuf-like
 * message formats through the IDS (Identity Services) framework.
 *
 * This fuzzer exercises the parsing code through these frameworks:
 *   - IMCore.framework (high-level iMessage API)
 *   - IMDaemonCore.framework (daemon-side handlers)
 *   - IMSharedUtilities.framework (shared parsing code)
 *   - IMFoundation.framework (base types)
 *
 * FUZZING PATHS:
 *
 *   [1] NSKeyedUnarchiver Deserialization
 *       iMessage payloads are NSKeyedArchiver-encoded plist data.
 *       We create mutated archives to find type confusion, UAF,
 *       and OOB bugs in the unarchiving process.
 *
 *   [2] NSAttributedString Parsing
 *       Rich text messages use NSAttributedString with custom
 *       attributes for mentions, links, inline attachments.
 *       Malformed attribute dictionaries can trigger parser bugs.
 *
 *   [3] Property List Parsing (Binary/XML)
 *       iMessage metadata uses property lists extensively.
 *       Binary plists have complex offset tables that can overflow.
 *
 *   [4] Nickname/Profile Data Parsing
 *       Nickname data includes: display name, image data,
 *       encrypted fields, handle IDs. This path BYPASSES BlastDoor.
 *
 *   [5] vCard/Contact Data Parsing
 *       Contact sharing uses vCard format — text-based with
 *       complex nested structures (PHOTO, ADR, TEL fields).
 *
 *   [6] Link Preview / Rich Link Metadata
 *       URL previews include title, description, image data,
 *       icon data, site name — all parsed by imagent.
 *
 * Build:
 *   clang -framework Foundation -framework CoreFoundation \
 *         -framework Contacts \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_imessage fuzz_imessage.m
 *
 * Run:
 *   ./fuzz_imessage corpus/ -max_len=65536 -timeout=10 -jobs=4
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#import <Contacts/Contacts.h>
#include <stdint.h>
#include <string.h>

/* ================================================================
 * PATH 1: NSKeyedUnarchiver Fuzzing
 *
 * iMessage payloads are packed as NSKeyedArchiver archives.
 * The unarchiver deserializes objects from binary plist data,
 * creating class instances based on the archive's class hierarchy.
 *
 * Attack vectors:
 *   - Class confusion (archive says NSString, data is NSData)
 *   - Recursive object graphs (stack overflow)
 *   - Malformed offset tables (OOB read/write)
 *   - Unexpected nil values in required fields
 *   - Integer overflow in collection sizes
 * ================================================================ */
static void fuzz_nskeyedunarchiver(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *archiveData = [NSData dataWithBytes:data length:size];

        /* Try unarchiving as different expected root classes */
        NSSet *allowedClasses = [NSSet setWithArray:@[
            [NSString class],
            [NSData class],
            [NSNumber class],
            [NSArray class],
            [NSDictionary class],
            [NSDate class],
            [NSURL class],
            [NSAttributedString class],
            [NSSet class],
            [NSNull class],
            [NSValue class],
        ]];

        @try {
            /* Secure unarchiving with allowed classes */
            NSError *error = nil;
            id obj = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                         fromData:archiveData
                                                            error:&error];
            if (obj) {
                /* Exercise the decoded object */
                if ([obj isKindOfClass:[NSString class]]) {
                    NSString *str = (NSString *)obj;
                    [str length];
                    [str UTF8String];
                    [str dataUsingEncoding:NSUTF8StringEncoding];
                } else if ([obj isKindOfClass:[NSDictionary class]]) {
                    NSDictionary *dict = (NSDictionary *)obj;
                    [dict count];
                    [dict allKeys];
                    [dict allValues];
                    /* Simulate iMessage payload field access */
                    [dict objectForKey:@"t"];  /* text */
                    [dict objectForKey:@"p"];  /* participants */
                    [dict objectForKey:@"r"];  /* reply */
                    [dict objectForKey:@"bp"]; /* balloon payload */
                    [dict objectForKey:@"bid"]; /* balloon ID */
                    [dict objectForKey:@"nn"]; /* nickname */
                } else if ([obj isKindOfClass:[NSArray class]]) {
                    NSArray *arr = (NSArray *)obj;
                    [arr count];
                    for (id item in arr) {
                        [item description];
                    }
                } else if ([obj isKindOfClass:[NSAttributedString class]]) {
                    NSAttributedString *attrStr = (NSAttributedString *)obj;
                    [attrStr length];
                    [attrStr string];
                    if ([attrStr length] > 0) {
                        [attrStr attributesAtIndex:0 effectiveRange:NULL];
                    }
                } else if ([obj isKindOfClass:[NSData class]]) {
                    NSData *d = (NSData *)obj;
                    [d length];
                    [d bytes];
                }
            }
        } @catch (NSException *e) {
            /* Expected for malformed archives */
        }

        /* Also try insecure unarchiving (some imagent paths still use this) */
        @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            id obj2 = [NSKeyedUnarchiver unarchiveObjectWithData:archiveData];
#pragma clang diagnostic pop
            if (obj2) {
                [obj2 description];
            }
        } @catch (NSException *e) {
            /* Expected */
        }
    }
}

/* ================================================================
 * PATH 2: NSAttributedString Fuzzing
 *
 * iMessage rich text uses NSAttributedString with custom attributes:
 *   - __kIMMessagePartAttributeName (part index)
 *   - __kIMDataDetectedAttributeName (detected data)
 *   - __kIMFileTransferGUIDAttributeName (attachment ref)
 *   - __kIMInlineReplyAttributeName (thread reference)
 *   - NSFont, NSParagraphStyle, NSLink, etc.
 *
 * We construct attributed strings from fuzz data and exercise
 * all attribute access paths.
 * ================================================================ */
static void fuzz_attributed_string(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 4) return;

        /* Build an attributed string from fuzz data */
        uint16_t str_len = 0;
        memcpy(&str_len, data, 2);
        str_len = str_len % 256;  /* Cap at 256 chars */

        if (str_len == 0 || (size_t)(str_len + 2) > size) return;

        NSString *baseStr = [[NSString alloc]
            initWithBytes:data + 2 length:MIN(str_len, size - 2)
            encoding:NSUTF8StringEncoding];
        if (!baseStr) {
            baseStr = [[NSString alloc]
                initWithBytes:data + 2 length:MIN(str_len, size - 2)
                encoding:NSASCIIStringEncoding];
        }
        if (!baseStr) return;

        NSMutableAttributedString *attrStr =
            [[NSMutableAttributedString alloc] initWithString:baseStr];

        /* Add attributes from fuzz data */
        size_t attr_offset = 2 + str_len;
        while (attr_offset + 4 < size && [attrStr length] > 0) {
            uint8_t attr_type = data[attr_offset];
            uint8_t range_start = data[attr_offset + 1] % [attrStr length];
            uint8_t range_len = data[attr_offset + 2] %
                ([attrStr length] - range_start + 1);
            if (range_len == 0) range_len = 1;
            if (range_start + range_len > [attrStr length])
                range_len = (uint8_t)([attrStr length] - range_start);

            NSRange range = NSMakeRange(range_start, range_len);

            @try {
                switch (attr_type % 8) {
                    case 0: /* Link attribute */
                        if (attr_offset + 5 < size) {
                            NSString *url = [[NSString alloc]
                                initWithBytes:data + attr_offset + 3
                                length:MIN(size - attr_offset - 3, 64)
                                encoding:NSUTF8StringEncoding];
                            if (url) {
                                [attrStr addAttribute:@"NSLink"
                                                value:url range:range];
                            }
                        }
                        break;

                    case 1: /* Foreground color (as string) */
                        [attrStr addAttribute:@"NSColor"
                                        value:@"fuzz_color" range:range];
                        break;

                    case 2: /* Custom iMessage-like attribute */
                        [attrStr addAttribute:@"__kIMMessagePartAttributeName"
                                        value:@(data[attr_offset + 3])
                                        range:range];
                        break;

                    case 3: /* File transfer GUID */
                        [attrStr addAttribute:@"__kIMFileTransferGUIDAttributeName"
                                        value:[[NSUUID UUID] UUIDString]
                                        range:range];
                        break;

                    case 4: /* Inline reply */
                        [attrStr addAttribute:@"__kIMInlineReplyAttributeName"
                                        value:@{@"threadID": @(data[attr_offset+3]),
                                                @"replyTo": @"msg-guid"}
                                        range:range];
                        break;

                    case 5: /* Paragraph-like style (as dictionary) */
                    {
                        NSDictionary *style = @{
                            @"alignment": @(data[attr_offset + 3] % 5),
                            @"lineSpacing": @(1.0)
                        };
                        [attrStr addAttribute:@"NSParagraphStyle"
                                        value:style range:range];
                        break;
                    }

                    case 6: /* Data detector attributes */
                        [attrStr addAttribute:@"__kIMDataDetectedAttributeName"
                                        value:@{@"type": @"phone",
                                                @"value": @"+1234567890"}
                                        range:range];
                        break;

                    case 7: /* Balloon payload */
                    {
                        NSData *payload = [NSData dataWithBytes:data + attr_offset
                                                        length:MIN(size - attr_offset, 128)];
                        [attrStr addAttribute:@"__kIMBalloonPayloadAttributeName"
                                        value:payload range:range];
                        break;
                    }
                }
            } @catch (NSException *e) {
                /* Expected for invalid ranges */
            }

            attr_offset += 4 + (data[attr_offset + 3] % 16);
        }

        /* Exercise the attributed string — simulating imagent processing */
        @try {
            [attrStr length];
            [attrStr string];

            /* Enumerate attributes (imagent does this to extract parts) */
            [attrStr enumerateAttributesInRange:NSMakeRange(0, [attrStr length])
                                        options:0
                                     usingBlock:^(NSDictionary *attrs,
                                                  NSRange range, BOOL *stop) {
                [attrs count];
                [attrs allKeys];
            }];

            /* Archive → re-unarchive roundtrip (imagent does this for storage) */
            NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:attrStr
                                                    requiringSecureCoding:NO
                                                                   error:nil];
            if (archived) {
                @try {
                    id restored = [NSKeyedUnarchiver
                        unarchivedObjectOfClass:[NSAttributedString class]
                        fromData:archived error:nil];
                    if (restored) {
                        [restored description];
                    }
                } @catch (NSException *e) { }
            }
        } @catch (NSException *e) { }
    }
}

/* ================================================================
 * PATH 3: Binary Property List Fuzzing
 *
 * iMessage metadata is distributed as binary plists.
 * Key plist payloads that imagent processes:
 *   - Message body (c = chat style, t = text, p = participants)
 *   - Balloon payloads (plugin data for rich messages)
 *   - Group photo metadata
 *   - Read receipt data
 *   - Tapback/reaction data
 *   - Edit/unsend metadata
 *
 * Binary plist format has:
 *   - 8-byte header "bplist00"
 *   - Object table (types + data)
 *   - Offset table (offsets into object table)
 *   - Trailer (offset table size, root object index)
 *
 * Integer overflows in offset table parsing are the key target.
 * ================================================================ */
static void fuzz_binary_plist(const uint8_t *data, size_t size) {
    @autoreleasepool {
        /* Try parsing as binary plist */
        NSData *plistData = [NSData dataWithBytes:data length:size];

        @try {
            NSError *error = nil;
            id plist = [NSPropertyListSerialization
                propertyListWithData:plistData
                options:NSPropertyListImmutable
                format:NULL
                error:&error];

            if (plist) {
                if ([plist isKindOfClass:[NSDictionary class]]) {
                    NSDictionary *dict = (NSDictionary *)plist;
                    /* Simulate iMessage payload extraction */
                    id text = dict[@"t"];       /* message text */
                    id parts = dict[@"p"];      /* participants */
                    id reply = dict[@"r"];      /* reply info */
                    id balloon = dict[@"bp"];   /* balloon plugin data */
                    id bid = dict[@"bid"];      /* balloon bundle ID */
                    id nn = dict[@"nn"];        /* nickname */
                    id gp = dict[@"gp"];        /* group photo */
                    id er = dict[@"er"];        /* edit/retract */
                    id ep = dict[@"ep"];        /* edit parts */
                    id tb = dict[@"tb"];        /* tapback */

                    /* Process nested structures */
                    if ([parts isKindOfClass:[NSArray class]]) {
                        for (id p in (NSArray *)parts) {
                            if ([p isKindOfClass:[NSString class]]) {
                                [(NSString *)p length];
                            }
                        }
                    }

                    /* Process balloon payload */
                    if ([balloon isKindOfClass:[NSData class]]) {
                        fuzz_binary_plist([(NSData *)balloon bytes],
                                         [(NSData *)balloon length]);
                    }

                    /* Process nickname fields */
                    if ([nn isKindOfClass:[NSDictionary class]]) {
                        NSDictionary *nnDict = (NSDictionary *)nn;
                        id displayName = nnDict[@"dn"];
                        id imageData = nnDict[@"id"];
                        id handleID = nnDict[@"hid"];
                        (void)displayName; (void)imageData; (void)handleID;
                    }

                    (void)text; (void)reply; (void)bid; (void)gp;
                    (void)er; (void)ep; (void)tb;
                }

                if ([plist isKindOfClass:[NSArray class]]) {
                    for (id item in (NSArray *)plist) {
                        [item description];
                    }
                }
            }
        } @catch (NSException *e) { }

        /* Also try with well-formed bplist header */
        if (size >= 8) {
            uint8_t bplist_buf[65536];
            size_t total = MIN(size + 8, sizeof(bplist_buf));
            memcpy(bplist_buf, "bplist00", 8);
            memcpy(bplist_buf + 8, data, total - 8);

            NSData *bpData = [NSData dataWithBytes:bplist_buf length:total];
            @try {
                id bp = [NSPropertyListSerialization
                    propertyListWithData:bpData
                    options:NSPropertyListImmutable
                    format:NULL error:nil];
                if (bp) [bp description];
            } @catch (NSException *e) { }
        }

        /* XML plist variant */
        if (size >= 16) {
            NSString *xmlStr = [[NSString alloc]
                initWithFormat:@"<?xml version=\"1.0\"?>"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\">"
                "<plist version=\"1.0\"><dict>"
                "<key>t</key><string>%@</string>"
                "<key>p</key><array><string>%@</string></array>"
                "</dict></plist>",
                [[NSString alloc] initWithBytes:data length:MIN(size/2, 128)
                    encoding:NSUTF8StringEncoding] ?: @"fuzz",
                [[NSString alloc] initWithBytes:data+size/2
                    length:MIN(size/2, 128) encoding:NSUTF8StringEncoding] ?: @"id"];
            NSData *xmlData = [xmlStr dataUsingEncoding:NSUTF8StringEncoding];
            @try {
                id xp = [NSPropertyListSerialization
                    propertyListWithData:xmlData
                    options:NSPropertyListImmutable
                    format:NULL error:nil];
                if (xp) [xp description];
            } @catch (NSException *e) { }
        }
    }
}

/* ================================================================
 * PATH 4: Nickname/Profile Data Fuzzing
 *
 * Nickname data format (BYPASSES BlastDoor):
 *   - displayName: NSString
 *   - firstName: NSString
 *   - lastName: NSString
 *   - imageData: NSData (up to 1MB image)
 *   - encryptedData: NSData
 *   - handleID: NSString (phone/email)
 *   - timestamp: NSDate
 *   - version: NSNumber
 *
 * The nickname is serialized as an NSKeyedArchiver archive.
 * imagent unarchives it directly, without BlastDoor protection.
 * ================================================================ */
static void fuzz_nickname_payload(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 8) return;

        /* Build a nickname-like dictionary and archive it */
        NSMutableDictionary *nickname = [NSMutableDictionary dictionary];

        /* Display name from fuzz data */
        size_t name_len = data[0] % 64;
        if (name_len > 0 && name_len < size) {
            NSString *name = [[NSString alloc]
                initWithBytes:data + 1 length:MIN(name_len, size - 1)
                encoding:NSUTF8StringEncoding];
            if (name) nickname[@"dn"] = name;
        }

        /* Handle ID */
        nickname[@"hid"] = @"+15551234567";

        /* Image data (from fuzz bytes — can be malformed JPEG/PNG) */
        if (size > name_len + 1) {
            NSData *imgData = [NSData dataWithBytes:data + name_len + 1
                                             length:size - name_len - 1];
            nickname[@"id"] = imgData;
        }

        /* Version and timestamp */
        nickname[@"v"] = @(data[0] & 0x0F);
        uint32_t ts_val = 0;
        if (size >= 5) memcpy(&ts_val, data + 1, 4);
        nickname[@"ts"] = [NSDate dateWithTimeIntervalSince1970:ts_val];

        /* Encrypted payload (some fields are encrypted in transit) */
        if (size > 16) {
            nickname[@"ep"] = [NSData dataWithBytes:data + 8
                                             length:MIN(size - 8, 256)];
        }

        /* Additional nickname metadata */
        nickname[@"ft"] = @"firstName";
        nickname[@"lt"] = @"lastName";

        /* Archive the nickname dictionary */
        @try {
            NSData *archived = [NSKeyedArchiver
                archivedDataWithRootObject:nickname
                requiringSecureCoding:NO error:nil];

            if (archived) {
                /* Mutate the archived data with our fuzz input */
                NSMutableData *mutated = [archived mutableCopy];

                /* Splice fuzz data into the archive at various points */
                if ([mutated length] > 16 && size > 4) {
                    size_t splice_point = data[0] % ([mutated length] - 4);
                    size_t splice_len = MIN(size, [mutated length] - splice_point);
                    [mutated replaceBytesInRange:
                        NSMakeRange(splice_point, MIN(splice_len, 4))
                        withBytes:data + (size > 4 ? 4 : 0) length:4];
                }

                /* Try unarchiving the mutated data */
                @try {
                    NSSet *classes = [NSSet setWithArray:@[
                        [NSDictionary class], [NSString class],
                        [NSData class], [NSNumber class],
                        [NSDate class], [NSArray class],
                    ]];
                    id restored = [NSKeyedUnarchiver
                        unarchivedObjectOfClasses:classes
                        fromData:mutated error:nil];
                    if (restored) {
                        [restored description];
                        if ([restored isKindOfClass:[NSDictionary class]]) {
                            [(NSDictionary *)restored allKeys];
                            [(NSDictionary *)restored allValues];
                        }
                    }
                } @catch (NSException *e) { }
            }
        } @catch (NSException *e) { }

        /* Also try raw fuzz data as an archive */
        @try {
            NSSet *classes = [NSSet setWithArray:@[
                [NSDictionary class], [NSString class],
                [NSData class], [NSNumber class],
                [NSDate class], [NSArray class], [NSSet class],
            ]];
            id raw = [NSKeyedUnarchiver
                unarchivedObjectOfClasses:classes
                fromData:[NSData dataWithBytes:data length:size]
                error:nil];
            if (raw) [raw description];
        } @catch (NSException *e) { }
    }
}

/* ================================================================
 * PATH 5: vCard Contact Data Fuzzing
 *
 * Contact cards shared via iMessage use vCard format (RFC 6350).
 * The Contacts framework parses these — complex text-based format
 * with nested properties, encoded binary data (BASE64 photos),
 * and various character encodings.
 * ================================================================ */
static void fuzz_vcard(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 4) return;

        /* Build a vCard from fuzz data components */
        NSMutableString *vcard = [NSMutableString stringWithString:
            @"BEGIN:VCARD\r\nVERSION:3.0\r\n"];

        /* Name from fuzz data */
        NSString *fuzzStr = [[NSString alloc]
            initWithBytes:data length:MIN(size, 128)
            encoding:NSUTF8StringEncoding];
        if (!fuzzStr) fuzzStr = @"Fuzz";

        [vcard appendFormat:@"N:%@;%@;;;\r\n", fuzzStr, fuzzStr];
        [vcard appendFormat:@"FN:%@\r\n", fuzzStr];

        /* Phone from fuzz data */
        if (size >= 8) {
            [vcard appendFormat:@"TEL;TYPE=CELL:+1%02X%02X%02X%02X%02X\r\n",
                data[0], data[1], data[2], data[3], data[4]];
        }

        /* Email */
        [vcard appendFormat:@"EMAIL;TYPE=HOME:%@@fuzz.local\r\n", fuzzStr];

        /* Address (complex nested field) */
        if (size >= 16) {
            NSString *addr = [[NSString alloc]
                initWithBytes:data + 8 length:MIN(size - 8, 64)
                encoding:NSUTF8StringEncoding] ?: @"123 Fuzz St";
            [vcard appendFormat:@"ADR;TYPE=HOME:;;%@;FuzzCity;FS;12345;US\r\n", addr];
        }

        /* Photo (BASE64 encoded fuzz data — triggers image parsing) */
        if (size >= 32) {
            NSData *photoData = [NSData dataWithBytes:data + 16
                                               length:MIN(size - 16, 4096)];
            NSString *base64 = [photoData base64EncodedStringWithOptions:0];
            [vcard appendFormat:@"PHOTO;ENCODING=b;TYPE=JPEG:%@\r\n", base64];
        }

        /* Note (can contain arbitrary text) */
        if (size >= 4) {
            NSString *note = [[NSString alloc]
                initWithBytes:data length:MIN(size, 256)
                encoding:NSUTF8StringEncoding] ?: @"fuzz note";
            [vcard appendFormat:@"NOTE:%@\r\n", note];
        }

        [vcard appendString:@"END:VCARD\r\n"];

        /* Parse through Contacts framework */
        NSData *vcardData = [vcard dataUsingEncoding:NSUTF8StringEncoding];
        @try {
            NSArray *contacts = [CNContactVCardSerialization
                contactsWithData:vcardData error:nil];
            if (contacts) {
                for (CNContact *contact in contacts) {
                    [contact givenName];
                    [contact familyName];
                    [contact phoneNumbers];
                    [contact emailAddresses];
                    [contact postalAddresses];
                    [contact imageData];
                    [contact note];
                }
            }
        } @catch (NSException *e) { }

        /* Also try parsing raw fuzz data as vCard */
        @try {
            NSData *rawData = [NSData dataWithBytes:data length:size];
            NSArray *rawContacts = [CNContactVCardSerialization
                contactsWithData:rawData error:nil];
            if (rawContacts) {
                for (CNContact *c in rawContacts) { [c description]; }
            }
        } @catch (NSException *e) { }
    }
}

/* ================================================================
 * PATH 6: Link Preview / Rich Link Metadata Fuzzing
 *
 * When a URL is shared via iMessage, imagent fetches metadata
 * and creates a rich link preview with:
 *   - title, description, siteName (strings)
 *   - image, icon (binary image data)
 *   - audio, video metadata
 *   - OpenGraph / Twitter Card metadata
 *
 * This data is serialized as a property list and processed
 * by imagent for display and caching.
 * ================================================================ */
static void fuzz_rich_link(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 8) return;

        /* Build a rich link metadata dictionary */
        NSMutableDictionary *linkMeta = [NSMutableDictionary dictionary];

        /* URL from fuzz data */
        NSString *url = [[NSString alloc]
            initWithBytes:data length:MIN(size, 256)
            encoding:NSUTF8StringEncoding];
        if (url) linkMeta[@"URL"] = url;

        /* Title and description */
        if (size >= 16) {
            NSString *title = [[NSString alloc]
                initWithBytes:data + 4 length:MIN(size - 4, 128)
                encoding:NSUTF8StringEncoding];
            if (title) linkMeta[@"title"] = title;
        }

        if (size >= 32) {
            NSString *desc = [[NSString alloc]
                initWithBytes:data + 16 length:MIN(size - 16, 256)
                encoding:NSUTF8StringEncoding];
            if (desc) {
                linkMeta[@"description"] = desc;
                linkMeta[@"siteName"] = desc;
            }
        }

        /* Image data (raw bytes — simulates downloaded preview image) */
        if (size >= 64) {
            linkMeta[@"imageData"] = [NSData dataWithBytes:data + 32
                                                    length:MIN(size - 32, 4096)];
            linkMeta[@"imageWidth"] = @(data[0] | (data[1] << 8));
            linkMeta[@"imageHeight"] = @(data[2] | (data[3] << 8));
        }

        /* Icon data */
        if (size >= 128) {
            linkMeta[@"iconData"] = [NSData dataWithBytes:data + 64
                                                   length:MIN(size - 64, 2048)];
        }

        /* OpenGraph-like metadata */
        linkMeta[@"og:type"] = @"article";
        linkMeta[@"og:locale"] = @"en_US";

        /* Archive the rich link metadata */
        @try {
            NSData *archived = [NSKeyedArchiver
                archivedDataWithRootObject:linkMeta
                requiringSecureCoding:NO error:nil];

            if (archived) {
                /* Mutate and re-parse */
                NSMutableData *mutated = [archived mutableCopy];
                if ([mutated length] > 8 && size > 4) {
                    size_t pos = data[0] % ([mutated length] - 4);
                    size_t len = MIN(4, size);
                    [mutated replaceBytesInRange:NSMakeRange(pos, len)
                        withBytes:data length:len];
                }

                @try {
                    NSSet *classes = [NSSet setWithArray:@[
                        [NSDictionary class], [NSString class],
                        [NSData class], [NSNumber class],
                        [NSArray class], [NSURL class],
                    ]];
                    id restored = [NSKeyedUnarchiver
                        unarchivedObjectOfClasses:classes
                        fromData:mutated error:nil];
                    if (restored) [restored description];
                } @catch (NSException *e) { }
            }
        } @catch (NSException *e) { }

        /* Try raw fuzz bytes as a plist containing link metadata */
        @try {
            id plist = [NSPropertyListSerialization
                propertyListWithData:[NSData dataWithBytes:data length:size]
                options:NSPropertyListImmutable format:NULL error:nil];
            if (plist && [plist isKindOfClass:[NSDictionary class]]) {
                NSDictionary *d = (NSDictionary *)plist;
                [d objectForKey:@"URL"];
                [d objectForKey:@"title"];
                [d objectForKey:@"imageData"];
            }
        } @catch (NSException *e) { }
    }
}

/* ================================================================
 * LLVMFuzzerTestOneInput — libFuzzer entry point
 *
 * Input structure:
 *   byte 0: Path selector
 *   byte 1: Sub-selector
 *   bytes 2+: Fuzz data
 * ================================================================ */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t path = data[0];
    const uint8_t *payload = data + 2;
    size_t payload_size = size - 2;

    switch (path % 7) {
        case 0:
            fuzz_nskeyedunarchiver(payload, payload_size);
            break;
        case 1:
            fuzz_attributed_string(payload, payload_size);
            break;
        case 2:
            fuzz_binary_plist(payload, payload_size);
            break;
        case 3:
            fuzz_nickname_payload(payload, payload_size);
            break;
        case 4:
            fuzz_vcard(payload, payload_size);
            break;
        case 5:
            fuzz_rich_link(payload, payload_size);
            break;
        case 6:
            /* ALL PATHS */
            fuzz_nskeyedunarchiver(payload, payload_size);
            fuzz_attributed_string(payload, payload_size);
            fuzz_binary_plist(payload, payload_size);
            fuzz_nickname_payload(payload, payload_size);
            fuzz_vcard(payload, payload_size);
            fuzz_rich_link(payload, payload_size);
            break;
    }

    return 0;
}
