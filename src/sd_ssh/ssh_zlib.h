/* sd_ssh private: zlib@openssh.com packet compression (01 section 4.7, decisions D6).
 *
 * Own implementation of RFC 1951 (DEFLATE) and RFC 1950 (zlib framing); no third-party code.
 * The compressed stream is continuous across SSH packets, the way OpenSSH's deflate()/inflate() use it:
 *   - the 2-byte zlib header is written once, before the first packet;
 *   - each packet is a non-final block followed by an empty static block (a partial flush, 10 bits), so
 *     the packet's symbols are complete in its bytes, while up to 7 bits of the empty block may wait for
 *     the next packet;
 *   - the 32 KiB history spans packets.
 * The decoder keeps the bits it has not consumed yet, plus the block state, between packets.
 * Decoded output is capped per packet (SSH_ZLIB_PACKET_MAX, the zip-bomb guard of 01 section 4.7).
 *
 * Not thread-safe: one encoder or decoder per SSH direction, used by the connection's I/O thread only. */
#ifndef SD_SSH_ZLIB_H
#define SD_SSH_ZLIB_H

#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"

#define SSH_ZLIB_WINDOW        (32u * 1024u)           /* RFC 1951 maximum distance */
#define SSH_ZLIB_PACKET_MAX    (256u * 1024u)          /* decompressed bytes per packet (zip-bomb limit) */

typedef struct ssh_zdef ssh_zdef;                       /* compressor */
typedef struct ssh_zinf ssh_zinf;                       /* decompressor */

ssh_zdef *ssh_zdef_new(void);                           /* NULL when out of memory */
void      ssh_zdef_free(ssh_zdef *z);
/* Appends the compressed form of one packet payload (1 .. SSH_ZLIB_PACKET_MAX bytes) to out. The output
   ends on a partial flush. SD_E_INVALID_PARAM for a bad size, SD_E_NO_MEMORY when out fails. */
sd_err ssh_zdef_compress(ssh_zdef *z, const uint8_t *in, size_t n, sd_wr *out);
/* Test support: final block and Adler-32 trailer, so the whole stream is a complete RFC 1950 stream. */
sd_err ssh_zdef_finish(ssh_zdef *z, sd_wr *out);

ssh_zinf *ssh_zinf_new(void);                           /* NULL when out of memory */
/* Same decoder; oneshot accepts the final block and the RFC 1950 trailer (tests and fuzz, never SSH). */
ssh_zinf *ssh_zinf_new_ex(int oneshot);
void      ssh_zinf_free(ssh_zinf *z);
/* Decodes the bytes of one packet. The output of this call is that packet's payload: at most cap bytes
   (SD_E_PROTOCOL beyond cap). Bytes that do not complete a symbol wait for the next call. Any malformed
   input makes the decoder fail for good (SD_E_PROTOCOL): the connection must be closed. */
sd_err ssh_zinf_packet(ssh_zinf *z, const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *outn);
/* Whole RFC 1950 stream in one buffer: header, blocks up to the final one, Adler-32, no trailing bytes.
   SD_E_PROTOCOL for anything else. Used by the unit tests and the fuzz target. */
sd_err ssh_zlib_oneshot(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *outn);

#endif /* SD_SSH_ZLIB_H */
