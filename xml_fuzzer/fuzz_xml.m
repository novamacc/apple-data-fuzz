/*
 * fuzz_xml.m — libxml2 / NSXMLParser / NSXMLDocument Fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: libxml2 + Foundation XML APIs
 *
 * libxml2 is used EVERYWHERE on Apple platforms:
 *   - Property lists (XML format)
 *   - SOAP/REST API responses
 *   - SVG rendering (in WebKit, CoreSVG)
 *   - Office document formats (OOXML, ODF)
 *   - RSS/Atom feed parsing
 *   - XHTML/HTML parsing in WebKit
 *   - Configuration files, entitlements
 *   - XPC message encoding
 *
 * libxml2 has a long history of CVEs (hundreds).
 * Apple ships a custom fork with additional patches.
 *
 * FUZZING PATHS (6):
 *   [0] NSXMLParser (SAX-style event parsing)
 *   [1] NSXMLDocument (DOM-style tree parsing)
 *   [2] XML property list round-trip
 *   [3] HTML parsing mode
 *   [4] XPath evaluation
 *   [5] DTD/entity expansion
 *
 * Build:
 *   clang -framework Foundation -framework CoreFoundation \
 *         -lxml2 -I/usr/include/libxml2 \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_xml fuzz_xml.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/HTMLparser.h>
#include <stdint.h>

/* ================================================================
 * PATH 0: NSXMLParser (SAX-style)
 *
 * This is the primary XML parsing API. Used by apps, frameworks,
 * and system services.
 * ================================================================ */
@interface FuzzDelegate : NSObject <NSXMLParserDelegate>
@property int depth;
@end

@implementation FuzzDelegate
- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)name
  namespaceURI:(NSString *)ns qualifiedName:(NSString *)qName
    attributes:(NSDictionary<NSString *, NSString *> *)attrs {
    self.depth++;
    (void)name.length;
    for (NSString *key in attrs) {
        (void)attrs[key].length;
    }
}
- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)name
  namespaceURI:(NSString *)ns qualifiedName:(NSString *)qName {
    self.depth--;
}
- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)string {
    (void)string.length;
}
- (void)parser:(NSXMLParser *)parser foundCDATA:(NSData *)CDATABlock {
    (void)CDATABlock.length;
}
- (void)parser:(NSXMLParser *)parser foundComment:(NSString *)comment {
    (void)comment.length;
}
- (void)parser:(NSXMLParser *)parser
  foundProcessingInstructionWithTarget:(NSString *)target data:(NSString *)data {
    (void)target; (void)data;
}
@end

static void fuzz_nsxml_sax(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];
        NSXMLParser *parser = [[NSXMLParser alloc] initWithData:nsdata];
        parser.shouldProcessNamespaces = YES;
        parser.shouldReportNamespacePrefixes = YES;
        parser.shouldResolveExternalEntities = NO; /* Security! */

        FuzzDelegate *delegate = [[FuzzDelegate alloc] init];
        parser.delegate = delegate;
        [parser parse];
    }
}

/* ================================================================
 * PATH 1: NSXMLDocument (DOM-style)
 * ================================================================ */
static void fuzz_nsxml_dom(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];
        NSError *error = nil;

        NSXMLDocument *doc = [[NSXMLDocument alloc]
            initWithData:nsdata
            options:NSXMLDocumentTidyXML | NSXMLNodePreserveAll
            error:&error];

        if (doc) {
            /* Walk the DOM tree */
            NSXMLElement *root = [doc rootElement];
            if (root) {
                (void)root.name;
                (void)root.childCount;

                /* Enumerate children */
                for (NSXMLNode *child in root.children) {
                    (void)child.name;
                    (void)child.stringValue;
                    (void)child.XMLString;
                }

                /* Get attributes */
                for (NSXMLNode *attr in root.attributes) {
                    (void)attr.name;
                    (void)attr.stringValue;
                }
            }

            /* Serialize back */
            NSData *output = [doc XMLData];
            (void)output.length;

            /* Pretty print */
            NSData *pretty = [doc XMLDataWithOptions:NSXMLNodePrettyPrint];
            (void)pretty.length;
        }
    }
}

/* ================================================================
 * PATH 2: XML property list round-trip
 * ================================================================ */
static void fuzz_xml_plist(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];

        /* Parse as XML plist */
        NSPropertyListFormat format;
        id plist = [NSPropertyListSerialization
            propertyListWithData:nsdata
            options:NSPropertyListMutableContainersAndLeaves
            format:&format
            error:NULL];

        if (plist && format == NSPropertyListXMLFormat_v1_0) {
            /* Re-serialize and re-parse */
            NSData *reserialized = [NSPropertyListSerialization
                dataWithPropertyList:plist
                format:NSPropertyListXMLFormat_v1_0
                options:0 error:NULL];

            if (reserialized) {
                id reparsed = [NSPropertyListSerialization
                    propertyListWithData:reserialized
                    options:NSPropertyListImmutable
                    format:NULL error:NULL];
                (void)reparsed;
            }
        }
    }
}

/* ================================================================
 * PATH 3: HTML parsing (libxml2 HTML parser)
 * ================================================================ */
static void fuzz_html(const uint8_t *data, size_t size) {
    @autoreleasepool {
        htmlDocPtr doc = htmlReadMemory(
            (const char *)data, (int)size,
            "fuzz.html", "UTF-8",
            HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING | HTML_PARSE_NONET);

        if (doc) {
            xmlNodePtr root = xmlDocGetRootElement(doc);
            if (root) {
                /* Walk tree */
                int nodeCount = 0;
                xmlNodePtr cur = root;
                while (cur && nodeCount < 1000) {
                    (void)cur->name;
                    if (cur->content) (void)strlen((char *)cur->content);

                    /* Get properties */
                    xmlAttrPtr attr = cur->properties;
                    while (attr && nodeCount < 1000) {
                        (void)attr->name;
                        attr = attr->next;
                        nodeCount++;
                    }

                    if (cur->children) {
                        cur = cur->children;
                    } else if (cur->next) {
                        cur = cur->next;
                    } else {
                        while (cur->parent && !cur->parent->next &&
                               cur->parent != (xmlNodePtr)doc) {
                            cur = cur->parent;
                        }
                        if (cur->parent) cur = cur->parent->next;
                        else cur = NULL;
                    }
                    nodeCount++;
                }
            }
            xmlFreeDoc(doc);
        }
    }
}

/* ================================================================
 * PATH 4: XPath evaluation
 * ================================================================ */
static void fuzz_xpath(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 4) return;

        /* Split: first byte = xpath query length, rest = XML */
        uint8_t qlen = data[0];
        if (qlen > size - 1) qlen = size - 1;
        if (qlen < 1) return;

        char xpath[256];
        int cpLen = qlen < 255 ? qlen : 255;
        memcpy(xpath, data + 1, cpLen);
        xpath[cpLen] = '\0';

        const uint8_t *xmlData = data + 1 + qlen;
        size_t xmlSize = size - 1 - qlen;
        if (xmlSize < 4) return;

        xmlDocPtr doc = xmlReadMemory(
            (const char *)xmlData, (int)xmlSize,
            "fuzz.xml", NULL,
            XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NONET);

        if (doc) {
            xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
            if (ctx) {
                xmlXPathObjectPtr result = xmlXPathEvalExpression(
                    (xmlChar *)xpath, ctx);
                if (result) {
                    if (result->type == XPATH_NODESET && result->nodesetval) {
                        int count = result->nodesetval->nodeNr;
                        for (int i = 0; i < count && i < 50; i++) {
                            xmlNodePtr node = result->nodesetval->nodeTab[i];
                            if (node && node->name) (void)strlen((char *)node->name);
                        }
                    }
                    xmlXPathFreeObject(result);
                }
                xmlXPathFreeContext(ctx);
            }
            xmlFreeDoc(doc);
        }
    }
}

/* ================================================================
 * PATH 5: DTD/entity processing
 * ================================================================ */
static void fuzz_dtd_entity(const uint8_t *data, size_t size) {
    @autoreleasepool {
        /* Parse with entity substitution enabled (but no external) */
        xmlDocPtr doc = xmlReadMemory(
            (const char *)data, (int)size,
            "fuzz.xml", NULL,
            XML_PARSE_DTDATTR | XML_PARSE_NOERROR |
            XML_PARSE_NOWARNING | XML_PARSE_NONET |
            XML_PARSE_DTDVALID);

        if (doc) {
            /* Get internal DTD */
            xmlDtdPtr dtd = xmlGetIntSubset(doc);
            if (dtd) {
                (void)dtd->name;
                (void)dtd->ExternalID;
                (void)dtd->SystemID;
            }

            /* Walk and expand entities */
            xmlNodePtr root = xmlDocGetRootElement(doc);
            if (root) {
                xmlChar *content = xmlNodeGetContent(root);
                if (content) {
                    (void)strlen((char *)content);
                    xmlFree(content);
                }
            }
            xmlFreeDoc(doc);
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
            case 0: fuzz_nsxml_sax(payload, psize);    break;
            case 1: fuzz_nsxml_dom(payload, psize);    break;
            case 2: fuzz_xml_plist(payload, psize);    break;
            case 3: fuzz_html(payload, psize);          break;
            case 4: fuzz_xpath(payload, psize);         break;
            case 5: fuzz_dtd_entity(payload, psize);   break;
        }
    }
    return 0;
}
