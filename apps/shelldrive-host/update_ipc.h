/* shelldrive-host update methods (04 §9.1, 03 §2.8): update.check and update.apply, and the events update.available
 * and update.progress. The engine is sd_update; this file owns the policy and settings reads (03 §3.5, 04 §9.1).
 *
 * Both methods answer through sd_ipc_defer: the network work runs on a worker thread and the reply is sent with
 * sd_ipc_reply_deferred, so the pipe thread never waits on the network. Only one check or apply runs at a time
 * (busy). */
#ifndef SD_HOST_UPDATE_IPC_H
#define SD_HOST_UPDATE_IPC_H

#include "sd_base/sd_json.h"
#include "sd_ipc/sd_ipc.h"

/* update.check {}: {enabled, reason?, available, version?, channel, notes?, size?, file_id?, released?, expires?,
   stale, stale_days?}. Disabled by policy/settings: enabled=false, no network. */
sd_err upd_method_check(sd_ipc_server *srv, sd_ipc_client *client, const sd_json *params, sd_json_writer *res,
                        sd_ipc_error *err);

/* update.apply {consent: true, version?}: consent is required. Reply {applied, version?, state}.
   Portable installs are not applied (update_disabled): the UI offers the manual download. */
sd_err upd_method_apply(sd_ipc_server *srv, sd_ipc_client *client, const sd_json *params, sd_json_writer *res,
                        sd_ipc_error *err);

#endif /* SD_HOST_UPDATE_IPC_H */
