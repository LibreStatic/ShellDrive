/* sd_state section helpers (03 §8.2.1): the agent's writer handle and the reader's one-call read of
 * Local\com.librestatic.shelldrive.state.<SID>. The owner and label checks happen in sd_ipc. */
#include <windows.h>

#include "sd_state/sd_state.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_base/sd_mem.h"

struct sd_state_writer {
  HANDLE h;
  uint8_t *view;
};

sd_err sd_state_writer_open(sd_state_writer **out)
{
  sd_state_writer *w;
  HANDLE h = NULL;
  int existed = 0;
  sd_err e;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  e = sd_ipc_state_create(&h, &existed);
  if (e != SD_OK)
    return e;
  w = (sd_state_writer *)sd_calloc(1, sizeof(*w));
  if (w == NULL) {
    CloseHandle(h);
    return SD_E_NO_MEMORY;
  }
  w->h = h;
  w->view = (uint8_t *)MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, SD_STATE_MAX_BYTES);
  if (w->view == NULL) {
    CloseHandle(h);
    sd_free(w);
    return SD_E_INTERNAL;
  }
  *out = w;
  return SD_OK;
}

sd_err sd_state_writer_publish(sd_state_writer *w, const sd_state_publish *in, uint32_t *truncated_entries)
{
  if (w == NULL || w->view == NULL)
    return SD_E_INVALID_PARAM;
  return sd_state_publish_buffer(w->view, SD_STATE_MAX_BYTES, in, truncated_entries);
}

void sd_state_writer_close(sd_state_writer *w)
{
  if (w == NULL)
    return;
  if (w->view)
    UnmapViewOfFile(w->view);
  if (w->h)
    CloseHandle(w->h);
  sd_free(w);
}

sd_err sd_state_read_section(sd_state_snapshot *snap)
{
  HANDLE h = NULL;
  const void *view;
  sd_err e;
  if (snap == NULL)
    return SD_E_INVALID_PARAM;
  e = sd_ipc_state_open(&h);
  if (e != SD_OK)
    return e;
  view = MapViewOfFile(h, FILE_MAP_READ, 0, 0, SD_STATE_MAX_BYTES);
  if (view == NULL) {
    CloseHandle(h);
    return SD_E_ACCESS_DENIED;
  }
  e = sd_state_read_buffer(view, SD_STATE_MAX_BYTES, snap);
  UnmapViewOfFile(view);
  CloseHandle(h);
  return e;
}
