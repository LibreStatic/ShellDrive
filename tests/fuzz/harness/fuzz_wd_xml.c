/* fuzz_wd_xml: WebDAV XML bodies (PROPFIND, PROPPATCH, LOCK; 00 section 4: no DTD, depth <= 32, body <= 1 MiB).
   The parser must reject DTDs and deep nesting and must stop at the end of the input. */
#include "sd_fuzz.h"
#include "wd_proto.h"

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  wd_xdoc doc;
  int ok;

  if (size > 64u * 1024u) return 0;
  memset(&doc, 0, sizeof(doc));
  ok = wd_xml_parse((const char *)data, size, &doc);
  if (ok) {
    int i;
    for (i = 0; i < (int)doc.count; i++) {
      (void)wd_xml_is(&doc, i, "DAV:", "prop");
      (void)wd_xml_child(&doc, i, "DAV:", "href");
    }
  }
  wd_xml_free(&doc);
  return 0;
}
