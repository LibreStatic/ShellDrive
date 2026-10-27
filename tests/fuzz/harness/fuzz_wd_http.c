/* fuzz_wd_http: WebDAV request head (request line, headers incl. Destination, Timeout, Range, If:, and the
   Sec-Fetch-* browser headers) and the chunked request-body decoder. The chunk sizes come from the input, so the
   incremental path sees split and whole reads. */
#include "sd_fuzz.h"
#include "wd_proto.h"

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  wd_req req;
  int status = 0;
  size_t off = 0;
  int ok;

  if (size > 64u * 1024u) return 0;
  memset(&req, 0, sizeof(req));
  ok = wd_http_parse_head((const char *)data, size, &req, &status);
  if (ok) {
    uint32_t count = 0;
    (void)wd_req_header(&req, "Destination", &count);
    (void)wd_req_header(&req, "Content-Length", &count);
    (void)wd_req_header(&req, "Transfer-Encoding", &count);
    (void)wd_req_has_prefix_header(&req, "Sec-Fetch-");
  }

  /* Chunked body: the first byte of the input chooses the feed size. */
  if (size) {
    wd_chunked c;
    size_t step = 1u + (data[0] & 0x3fu);
    wd_chunked_init(&c);
    while (off < size) {
      size_t n = size - off < step ? size - off : step;
      size_t used = 0, dn = 0;
      const char *d = NULL;
      int rc = wd_chunked_feed(&c, (const char *)data + off, n, &used, &d, &dn);
      SD_FUZZ_CHECK(used <= n);
      SD_FUZZ_CHECK(dn <= n);
      if (rc != 0 || used == 0) {
        if (used == 0) off += n; /* no progress: skip the piece */
        else off += used;
        if (rc != 0) break;
        continue;
      }
      off += used;
    }
  }
  return 0;
}
