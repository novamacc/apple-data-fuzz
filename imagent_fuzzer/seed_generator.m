/*
 * seed_generator.m — Generate iMessage protocol seed corpus
 *
 * Creates valid seed files for:
 *   - NSKeyedArchiver archives (various root object types)
 *   - NSAttributedString with custom attributes
 *   - Binary plists (message payloads, nickname data)
 *   - vCard contacts
 *   - Rich link metadata
 *
 * Build:
 *   clang -framework Foundation -framework Contacts -o seed_generator seed_generator.m
 *
 * Run:
 *   ./seed_generator corpus/
 */

#import <Foundation/Foundation.h>
#import <Contacts/Contacts.h>
#include <sys/stat.h>

static void write_seed(const char *dir, const char *name,
                        NSData *data) {
    NSString *path = [NSString stringWithFormat:@"%s/%s", dir, name];
    [data writeToFile:path atomically:YES];
    printf("  [+] %-45s (%6lu bytes)\n", name, (unsigned long)[data length]);
}

/* ── NSKeyedArchiver seeds ── */
static void gen_archive_seeds(const char *dir) {
    /* String archive */
    NSData *strArchive = [NSKeyedArchiver archivedDataWithRootObject:@"Hello iMessage"
        requiringSecureCoding:NO error:nil];
    if (strArchive) write_seed(dir, "archive_string.bin", strArchive);

    /* Dictionary archive (iMessage payload-like) */
    NSDictionary *msgPayload = @{
        @"t": @"Hello from fuzzer",
        @"p": @[@"+15551234567", @"+15559876543"],
        @"r": @"msg-guid-12345",
        @"v": @(1),
        @"gid": @"group-chat-uuid"
    };
    NSData *dictArchive = [NSKeyedArchiver archivedDataWithRootObject:msgPayload
        requiringSecureCoding:NO error:nil];
    if (dictArchive) write_seed(dir, "archive_msg_payload.bin", dictArchive);

    /* Array archive */
    NSData *arrArchive = [NSKeyedArchiver archivedDataWithRootObject:
        @[@"part1", @"part2", @(42), [NSNull null]]
        requiringSecureCoding:NO error:nil];
    if (arrArchive) write_seed(dir, "archive_array.bin", arrArchive);

    /* Nested dictionary (balloon payload) */
    NSDictionary *balloon = @{
        @"bid": @"com.apple.messages.MSMessageExtensionBalloonPlugin",
        @"bp": [@"balloon-payload-data" dataUsingEncoding:NSUTF8StringEncoding],
        @"an": @"App Name",
        @"ai": @"app-icon-data"
    };
    NSData *balloonArchive = [NSKeyedArchiver archivedDataWithRootObject:balloon
        requiringSecureCoding:NO error:nil];
    if (balloonArchive) write_seed(dir, "archive_balloon.bin", balloonArchive);

    /* NSData archive */
    NSData *dataArchive = [NSKeyedArchiver archivedDataWithRootObject:
        [@"binary payload" dataUsingEncoding:NSUTF8StringEncoding]
        requiringSecureCoding:NO error:nil];
    if (dataArchive) write_seed(dir, "archive_data.bin", dataArchive);

    /* Date archive */
    NSData *dateArchive = [NSKeyedArchiver archivedDataWithRootObject:[NSDate date]
        requiringSecureCoding:NO error:nil];
    if (dateArchive) write_seed(dir, "archive_date.bin", dateArchive);
}

/* ── NSAttributedString seeds ── */
static void gen_attrstr_seeds(const char *dir) {
    /* Simple attributed string */
    NSMutableAttributedString *simple = [[NSMutableAttributedString alloc]
        initWithString:@"Hello World"];
    [simple addAttribute:@"NSLink" value:@"https://apple.com"
        range:NSMakeRange(0, 5)];
    NSData *simpleArchive = [NSKeyedArchiver archivedDataWithRootObject:simple
        requiringSecureCoding:NO error:nil];
    if (simpleArchive) write_seed(dir, "attrstr_link.bin", simpleArchive);

    /* Attributed string with iMessage-like attributes */
    NSMutableAttributedString *imsg = [[NSMutableAttributedString alloc]
        initWithString:@"Hey @John check this out!"];
    [imsg addAttribute:@"__kIMMessagePartAttributeName" value:@(0)
        range:NSMakeRange(0, 24)];
    [imsg addAttribute:@"__kIMDataDetectedAttributeName"
        value:@{@"type": @"mention", @"id": @"+15551234567"}
        range:NSMakeRange(4, 5)];
    NSData *imsgArchive = [NSKeyedArchiver archivedDataWithRootObject:imsg
        requiringSecureCoding:NO error:nil];
    if (imsgArchive) write_seed(dir, "attrstr_imessage.bin", imsgArchive);

    /* Long attributed string (stress test) */
    NSMutableString *longStr = [NSMutableString string];
    for (int i = 0; i < 100; i++) [longStr appendString:@"ABCDEFGHIJ"];
    NSMutableAttributedString *longAttr = [[NSMutableAttributedString alloc]
        initWithString:longStr];
    for (int i = 0; i < 50; i++) {
        [longAttr addAttribute:@"__kIMMessagePartAttributeName"
            value:@(i) range:NSMakeRange(i * 20, 20)];
    }
    NSData *longArchive = [NSKeyedArchiver archivedDataWithRootObject:longAttr
        requiringSecureCoding:NO error:nil];
    if (longArchive) write_seed(dir, "attrstr_long.bin", longArchive);
}

/* ── Binary plist seeds ── */
static void gen_plist_seeds(const char *dir) {
    /* Simple message plist */
    NSDictionary *msg = @{@"t": @"hello", @"p": @[@"+15551234567"]};
    NSData *bplist = [NSPropertyListSerialization
        dataWithPropertyList:msg format:NSPropertyListBinaryFormat_v1_0
        options:0 error:nil];
    if (bplist) write_seed(dir, "plist_message.bin", bplist);

    /* Nickname plist */
    NSDictionary *nn = @{
        @"dn": @"John Doe",
        @"hid": @"+15551234567",
        @"v": @(2),
        @"id": [@"fake-image-data" dataUsingEncoding:NSUTF8StringEncoding],
        @"ep": [@"encrypted-payload" dataUsingEncoding:NSUTF8StringEncoding]
    };
    NSData *nnPlist = [NSPropertyListSerialization
        dataWithPropertyList:nn format:NSPropertyListBinaryFormat_v1_0
        options:0 error:nil];
    if (nnPlist) write_seed(dir, "plist_nickname.bin", nnPlist);

    /* Group photo metadata */
    NSDictionary *gp = @{
        @"gid": @"group-uuid-12345",
        @"path": @"/tmp/groupphoto.jpg",
        @"ts": @(1711700000),
        @"sz": @(65536)
    };
    NSData *gpPlist = [NSPropertyListSerialization
        dataWithPropertyList:gp format:NSPropertyListBinaryFormat_v1_0
        options:0 error:nil];
    if (gpPlist) write_seed(dir, "plist_groupphoto.bin", gpPlist);

    /* Edit/unsend metadata */
    NSDictionary *edit = @{
        @"er": @{@"guid": @"msg-guid-to-edit", @"part": @(0)},
        @"ep": @{@"newText": @"Edited message", @"ts": @(1711700100)}
    };
    NSData *editPlist = [NSPropertyListSerialization
        dataWithPropertyList:edit format:NSPropertyListBinaryFormat_v1_0
        options:0 error:nil];
    if (editPlist) write_seed(dir, "plist_edit.bin", editPlist);

    /* Tapback/reaction */
    NSDictionary *tapback = @{
        @"tb": @{@"guid": @"msg-guid", @"type": @(2000), @"assocPart": @(0)}
    };
    NSData *tbPlist = [NSPropertyListSerialization
        dataWithPropertyList:tapback format:NSPropertyListBinaryFormat_v1_0
        options:0 error:nil];
    if (tbPlist) write_seed(dir, "plist_tapback.bin", tbPlist);

    /* XML plist variant */
    NSDictionary *xmlDict = @{@"t": @"xml test", @"v": @(1)};
    NSData *xmlPlist = [NSPropertyListSerialization
        dataWithPropertyList:xmlDict format:NSPropertyListXMLFormat_v1_0
        options:0 error:nil];
    if (xmlPlist) write_seed(dir, "plist_xml.bin", xmlPlist);
}

/* ── vCard seeds ── */
static void gen_vcard_seeds(const char *dir) {
    /* Simple vCard */
    NSString *simple = @"BEGIN:VCARD\r\nVERSION:3.0\r\n"
        "N:Doe;John;;;\r\nFN:John Doe\r\n"
        "TEL;TYPE=CELL:+15551234567\r\n"
        "EMAIL:john@example.com\r\n"
        "END:VCARD\r\n";
    write_seed(dir, "vcard_simple.bin",
        [simple dataUsingEncoding:NSUTF8StringEncoding]);

    /* Complex vCard with photo */
    NSString *complex_ = @"BEGIN:VCARD\r\nVERSION:3.0\r\n"
        "N:Smith;Jane;;Dr.;\r\nFN:Dr. Jane Smith\r\n"
        "ORG:Apple Inc.\r\nTITLE:Security Engineer\r\n"
        "TEL;TYPE=WORK:+15559876543\r\nTEL;TYPE=CELL:+15551111111\r\n"
        "EMAIL;TYPE=WORK:jane@apple.com\r\n"
        "ADR;TYPE=WORK:;;1 Apple Park Way;Cupertino;CA;95014;US\r\n"
        "PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRg==\r\n"
        "NOTE:Security team member\r\n"
        "END:VCARD\r\n";
    write_seed(dir, "vcard_complex.bin",
        [complex_ dataUsingEncoding:NSUTF8StringEncoding]);

    /* vCard with all field types */
    NSString *allFields = @"BEGIN:VCARD\r\nVERSION:4.0\r\n"
        "N:Test;Multi;Middle;Prof.;Jr.\r\nFN:Prof. Multi Middle Test Jr.\r\n"
        "NICKNAME:Fuzzy\r\nBDAY:19900101\r\n"
        "TEL;TYPE=home:+15550000000\r\nTEL;TYPE=work:+15550000001\r\n"
        "EMAIL;TYPE=home:a@b.c\r\nEMAIL;TYPE=work:d@e.f\r\n"
        "ADR;TYPE=home:;;123 Main St;City;ST;12345;US\r\n"
        "URL:https://example.com\r\nNOTE:All fields test\r\n"
        "IMPP;TYPE=HOME:xmpp:user@server\r\n"
        "END:VCARD\r\n";
    write_seed(dir, "vcard_allfields.bin",
        [allFields dataUsingEncoding:NSUTF8StringEncoding]);
}

/* ── Rich link seeds ── */
static void gen_richlink_seeds(const char *dir) {
    NSDictionary *link = @{
        @"URL": @"https://www.apple.com/iphone/",
        @"title": @"iPhone - Apple",
        @"description": @"Explore iPhone, the world's most powerful phone.",
        @"siteName": @"Apple",
        @"imageWidth": @(1200),
        @"imageHeight": @(630),
        @"imageData": [@"fake-jpeg-data" dataUsingEncoding:NSUTF8StringEncoding]
    };
    NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:link
        requiringSecureCoding:NO error:nil];
    if (archived) write_seed(dir, "richlink_apple.bin", archived);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        const char *dir = argc > 1 ? argv[1] : "corpus";
        mkdir(dir, 0755);

        printf("[*] Generating iMessage protocol seed corpus in %s/\n\n", dir);

        printf("  NSKeyedArchiver archives:\n");
        gen_archive_seeds(dir);

        printf("\n  NSAttributedString:\n");
        gen_attrstr_seeds(dir);

        printf("\n  Binary plists:\n");
        gen_plist_seeds(dir);

        printf("\n  vCard contacts:\n");
        gen_vcard_seeds(dir);

        printf("\n  Rich link metadata:\n");
        gen_richlink_seeds(dir);

        printf("\n[+] Seed corpus generation complete.\n");
        return 0;
    }
}
