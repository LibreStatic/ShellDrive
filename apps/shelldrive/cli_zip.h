/* Stored (uncompressed) ZIP writer for "shelldrive diag --bundle" (03 §10.5). No compression and no
 * zlib: the bundle is a plain archive of text files that the user attaches by hand. Entries use a data
 * descriptor (general purpose flag bit 3), so the size and the CRC of an entry need not be known before
 * its data is written; names are UTF-8 (flag bit 11). The archive is the classic format (no Zip64): fewer
 * than 65536 entries and less than 4 GiB in all, otherwise the add and finish calls fail with SD_E_FAILURE. */
#ifndef CLI_ZIP_H
#define CLI_ZIP_H

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

/* Receives the archive bytes in order. Returns 0 on success, non-zero to abort the archive. */
typedef int (*zip_sink_fn)(void *ctx, const void *p, size_t n);

typedef struct zip_writer zip_writer;

/* Creates a writer; sink receives every byte. NULL when out of memory or sink is NULL. */
zip_writer *zip_open(zip_sink_fn sink, void *ctx);
/* Releases the writer; it does not finish the archive. */
void zip_free(zip_writer *w);

/* One entry: zip_add_begin, zip_add_data (any number of times), zip_add_end. name is UTF-8, relative, with
   forward slashes, no leading slash, no backslash, no "..", at most 255 bytes. when may be NULL (1980-01-01). */
sd_err zip_add_begin(zip_writer *w, const char *name, const SYSTEMTIME *when);
sd_err zip_add_data(zip_writer *w, const void *p, size_t n);
sd_err zip_add_end(zip_writer *w);
/* Writes the central directory and the end record. No entry can be added afterwards. */
sd_err zip_finish(zip_writer *w);

/* Entries completed so far, and the bytes written so far. */
uint32_t zip_entry_count(const zip_writer *w);
uint64_t zip_bytes(const zip_writer *w);

/* CRC-32 (IEEE 802.3, as ZIP uses it). Pass 0 as crc to start a new stream. */
uint32_t zip_crc32(uint32_t crc, const void *p, size_t n);

#endif /* CLI_ZIP_H */
