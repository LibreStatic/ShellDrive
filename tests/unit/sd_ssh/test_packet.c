/* Binary packet protocol: framing without encryption (always), and every M0 cipher/MAC pair when
 * sd_crypto is complete. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "ssh_internal.h"
#include "test_util.h"

static void feed_all(sd_test_ctx *sd_t_, ssh_dir *rx, uint8_t *buf, size_t len, uint32_t expect_packets,
                     size_t step)
{
  /* Feeds the stream in `step`-sized growing windows to exercise partial input. */
  size_t off = 0, avail = 0;
  uint32_t got = 0;
  while (off < len) {
    size_t used = 0;
    sd_span pl;
    sd_err e;
    avail = SD_MIN(avail + step, len - off);
    e = ssh_pkt_open(rx, buf + off, avail, &used, &pl);
    SD_REQUIRE(e == SD_OK);
    if (!pl.p) { SD_REQUIRE(avail < len - off); continue; }
    SD_CHECK(pl.n == (size_t)(got * 37 + 1));
    SD_CHECK(pl.p[0] == (uint8_t)(got + 100));
    off += used;
    avail -= used;
    got++;
  }
  SD_CHECK_EQ_INT(got, expect_packets);
}

static void seal_n(sd_test_ctx *sd_t_, ssh_dir *tx, sd_wr *w, uint32_t n)
{
  uint32_t i;
  for (i = 0; i < n; i++) {
    uint8_t pl[2048];
    size_t len = i * 37 + 1;
    memset(pl, (int)i, len);
    pl[0] = (uint8_t)(i + 100);
    SD_REQUIRE(ssh_pkt_seal(tx, pl, len, w) == SD_OK);
  }
}

SD_TEST(ssh_packet_plain_framing)
{
  ssh_dir tx, rx;
  sd_wr w;
  ssh_set_random_for_tests(tu_det_random);
  ssh_dir_init(&tx);
  ssh_dir_init(&rx);
  sd_wr_init(&w, 1u << 24);
  seal_n(sd_t_, &tx, &w, 20);
  SD_CHECK_EQ_INT(tx.seq, 20);
  /* every packet is a multiple of 8 and at least 16 bytes */
  {
    size_t off = 0;
    while (off < w.len) {
      uint32_t plen = sd_load_be32(w.p + off);
      SD_CHECK((plen + 4) % 8 == 0);
      SD_CHECK(plen + 4 >= 16);
      SD_CHECK(w.p[off + 4] >= 4);
      off += plen + 4;
    }
  }
  feed_all(sd_t_, &rx, w.p, w.len, 20, 3);
  SD_CHECK_EQ_INT(rx.seq, 20);
  sd_wr_free(&w);
  ssh_set_random_for_tests(NULL);
}

SD_TEST(ssh_packet_rejects_bad_framing)
{
  ssh_dir rx;
  uint8_t pkt[64];
  size_t used;
  sd_span pl;
  ssh_dir_init(&rx);
  /* length too large */
  memset(pkt, 0, sizeof(pkt));
  sd_store_be32(pkt, SSH_MAX_PACKET_LEN + 8);
  SD_CHECK_EQ_INT(ssh_pkt_open(&rx, pkt, sizeof(pkt), &used, &pl), SD_E_PROTOCOL);
  /* not a block multiple */
  ssh_dir_init(&rx);
  sd_store_be32(pkt, 13);
  SD_CHECK_EQ_INT(ssh_pkt_open(&rx, pkt, sizeof(pkt), &used, &pl), SD_E_PROTOCOL);
  /* padding shorter than 4 */
  ssh_dir_init(&rx);
  sd_store_be32(pkt, 12);
  pkt[4] = 3;
  SD_CHECK_EQ_INT(ssh_pkt_open(&rx, pkt, 16, &used, &pl), SD_E_PROTOCOL);
  /* padding eats the whole packet */
  ssh_dir_init(&rx);
  sd_store_be32(pkt, 12);
  pkt[4] = 11;
  SD_CHECK_EQ_INT(ssh_pkt_open(&rx, pkt, 16, &used, &pl), SD_E_PROTOCOL);
  /* fine: 12 = 1 + 7 payload + 4 padding */
  ssh_dir_init(&rx);
  sd_store_be32(pkt, 12);
  pkt[4] = 4;
  pkt[5] = 2;
  SD_CHECK_EQ_INT(ssh_pkt_open(&rx, pkt, 16, &used, &pl), SD_OK);
  SD_CHECK(pl.p && pl.n == 7 && used == 16 && pl.p[0] == 2);
}

typedef struct combo { const char *cipher, *mac; } combo;

SD_TEST(ssh_packet_ciphers_roundtrip)
{
  static const combo k_combos[] = {
    { "chacha20-poly1305@openssh.com", NULL }, { "aes256-gcm@openssh.com", NULL },
    { "aes128-gcm@openssh.com", NULL }, { "aes256-ctr", "hmac-sha2-256-etm@openssh.com" },
    { "aes192-ctr", "hmac-sha2-512-etm@openssh.com" }, { "aes128-ctr", "hmac-sha2-256" },
    { "aes256-ctr", "hmac-sha2-512" }
  };
  size_t i;
  if (!tu_crypto_or_skip("ssh_packet_ciphers_roundtrip")) return;
  for (i = 0; i < SD_COUNTOF(k_combos); i++) {
    ssh_dir tx, rx;
    sd_wr w;
    uint8_t key[64], iv[32], mk[64];
    size_t kl, il, ml;
    SD_REQUIRE(ssh_alg_key_sizes(k_combos[i].cipher, k_combos[i].mac, &kl, &il, &ml) == SD_OK);
    tu_det_random(key, sizeof(key));
    tu_det_random(iv, sizeof(iv));
    tu_det_random(mk, sizeof(mk));
    ssh_dir_init(&tx);
    ssh_dir_init(&rx);
    tx.seq = rx.seq = 0xFFFFFFF0u;   /* sequence wrap inside the run */
    SD_REQUIRE(ssh_dir_set_keys(&tx, 1, k_combos[i].cipher, k_combos[i].mac, key, iv, mk) == SD_OK);
    SD_REQUIRE(ssh_dir_set_keys(&rx, 0, k_combos[i].cipher, k_combos[i].mac, key, iv, mk) == SD_OK);
    tx.seq = rx.seq = 0xFFFFFFF0u;
    sd_wr_init(&w, 1u << 24);
    seal_n(sd_t_, &tx, &w, 40);
    feed_all(sd_t_, &rx, w.p, w.len, 40, 5);
    /* tamper with the next packet: authentication must fail */
    sd_wr_reset(&w);
    seal_n(sd_t_, &tx, &w, 1);
    w.p[w.len - 1] ^= 1;
    {
      size_t used;
      sd_span pl;
      SD_CHECK_EQ_INT(ssh_pkt_open(&rx, w.p, w.len, &used, &pl), SD_E_CRYPTO);
    }
    sd_wr_free(&w);
    ssh_dir_clear(&tx);
    ssh_dir_clear(&rx);
  }
}

/* Delayed zlib@openssh.com (01 section 4.7): plain packets until the switch, compressed packets after it, one
   continuous stream per direction. No cipher: framing only. */
SD_TEST(ssh_packet_zlib_delayed)
{
  enum { NPKT = 24 };
  ssh_dir tx, rx;
  sd_wr w;
  size_t off = 0, k;
  size_t plain_bytes = 0, wire_comp = 0;
  uint8_t pl[4096];

  ssh_dir_init(&tx);
  ssh_dir_init(&rx);
  tx.comp.tx = 1;
  ssh_dir_set_comp_name(&tx, "zlib@openssh.com");
  ssh_dir_set_comp_name(&rx, "zlib@openssh.com");
  sd_wr_init(&w, 1u << 22);

  /* before USERAUTH_SUCCESS nothing is compressed */
  memset(pl, 'p', 64);
  SD_REQUIRE(ssh_pkt_seal(&tx, pl, 64, &w) == SD_OK);
  SD_CHECK(!tx.comp.on && !rx.comp.on);
  /* the first plain packet is a complete plain packet of 64 bytes */
  {
    size_t used = 0;
    sd_span pls;
    SD_REQUIRE(ssh_pkt_open(&rx, w.p, w.len, &used, &pls) == SD_OK);
    SD_REQUIRE(pls.p != NULL && pls.n == 64 && memcmp(pls.p, pl, 64) == 0);
    off = used;
  }

  /* USERAUTH_SUCCESS: both directions switch, from the next packet on */
  SD_REQUIRE(ssh_dir_comp_start(&tx) == SD_OK);
  SD_REQUIRE(ssh_dir_comp_start(&rx) == SD_OK);
  SD_CHECK(tx.comp.on && rx.comp.on);
  for (k = 0; k < NPKT; k++) {
    size_t n = 200 + k * 97, before = w.len;
    size_t i, used = 0;
    sd_span pls;
    for (i = 0; i < n; i++) pl[i] = (uint8_t)("abcdefgh"[(i / 7 + k) % 8]);
    SD_REQUIRE(ssh_pkt_seal(&tx, pl, n, &w) == SD_OK);
    plain_bytes += n;
    wire_comp += w.len - before;
    /* decode this packet right away, as the connection does */
    SD_REQUIRE(ssh_pkt_open(&rx, w.p + off, w.len - off, &used, &pls) == SD_OK);
    SD_REQUIRE(pls.p != NULL);
    SD_CHECK(pls.n == n && memcmp(pls.p, pl, n) == 0);
    off += used;
  }
  SD_CHECK(off == w.len);
  SD_CHECK(wire_comp < plain_bytes / 2);     /* repetitive payloads shrink */
  SD_CHECK(tx.seq == NPKT + 1 && rx.seq == NPKT + 1);

  /* a re-key that negotiates none ends compression in that direction */
  ssh_dir_set_comp_name(&rx, "none");
  SD_CHECK(!rx.comp.on);
  ssh_dir_set_comp_name(&tx, "none");
  SD_CHECK(!tx.comp.on);

  sd_wr_free(&w);
  ssh_dir_clear(&tx);
  ssh_dir_clear(&rx);
}
