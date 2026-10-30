/* Pure rules of the diag checks (03 §10.5, 02 §6.3, 04 §9.2, 03 §8.7): versions, the dokany-deny list of a
 * manifest and the sync of Network location entries. No system call is made here, so the unit tests run the
 * rules on plain text. */
#ifndef CLI_DIAG_RULES_H
#define CLI_DIAG_RULES_H

#include <stddef.h>
#include <stdint.h>

/* major * 1000000 + minor * 1000 + patch. 0 means unknown. */
uint32_t diag_version_pack(unsigned major, unsigned minor, unsigned patch);

/* "2.3.1" or "2.3.1.1000" (a fourth part is ignored, a missing patch is 0). 0 when malformed. */
uint32_t diag_version_parse(const char *s, size_t len);

/* The text of a version: "2.3.1". */
void diag_version_text(uint32_t packed, char *out, size_t cap);

#define DIAG_DENY_MAX 16
#define DIAG_DENY_REASON 40

typedef struct diag_deny_range {
  uint32_t from, to;                     /* inclusive, packed */
  char reason[DIAG_DENY_REASON];         /* the reason-id of the manifest line */
} diag_deny_range;

typedef struct diag_deny_list {
  int count;
  diag_deny_range range[DIAG_DENY_MAX];
} diag_deny_list;

/* Adds the "dokany-deny <min>-<max> <reason-id>" lines of a manifest text. Other lines are ignored; a malformed
   deny line is ignored too (it cannot widen the list). Full lists are truncated at DIAG_DENY_MAX. */
void diag_deny_parse(diag_deny_list *d, const char *text, size_t len);

/* The reason of the first range that contains ver, or NULL. */
const char *diag_deny_match(const diag_deny_list *d, uint32_t ver);

/* Compares the ids of our Network location entries (present) with the profiles that want one (wanted). Both
   are token lists: ids separated by newlines, commas or blanks. missing = wanted but absent, stale = present
   but not wanted, wanted_count = the number of wanted ids. */
void diag_netloc_compare(const char *present, const char *wanted, int *missing, int *stale, int *wanted_count);

#endif /* CLI_DIAG_RULES_H */
