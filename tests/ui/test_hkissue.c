/* Changed key and wrong key type (apps/shelldrive-ui/ui_hkissue_model.c, 03 §5.4, TM-R04): the mount.state error is read,
   the store of the old key is told from its path and the dialog offers only what makes sense for that store. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_base/sd_json.h"
#include "ui_hkissue_model.h"

static sd_json *parse(const char *text)
{
  sd_json *j = NULL;
  if (sd_json_parse(text, strlen(text), 0, &j) != SD_OK)
    return NULL;
  return j;
}

SD_TEST(hkissue_mismatch_event_is_read)
{
  static const char ev[] =
      "{\"mount_id\":\"m-1\",\"state\":\"failed\",\"error\":{\"code\":\"host_key_mismatch\",\"detail\":\"d\","
      "\"exit_code\":6,\"host\":\"example.org\",\"stored_type\":\"ssh-ed25519\",\"stored_fp\":\"SHA256:old\","
      "\"offered_type\":\"ssh-ed25519\",\"offered_fp\":\"SHA256:new\","
      "\"store_path\":\"C:\\\\Users\\\\a\\\\.ssh\\\\known_hosts\",\"store_line\":12}}";
  sd_json *j = parse(ev);
  ui_hki h;
  SD_CHECK(j != NULL);
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "other.example", &h), (int)UI_HKI_CHANGED);
  SD_CHECK_STR(h.host, "example.org");
  SD_CHECK_STR(h.mount_id, "m-1");
  SD_CHECK_STR(h.stored_fp, "SHA256:old");
  SD_CHECK_STR(h.offered_fp, "SHA256:new");
  SD_CHECK(wcscmp(h.path, L"C:\\Users\\a\\.ssh\\known_hosts") == 0);
  SD_CHECK_EQ_INT((int)h.line, 12);
  sd_json_free(j);
}

SD_TEST(hkissue_other_errors_and_missing_fields)
{
  sd_json *j = parse("{\"mount_id\":\"m\",\"state\":\"failed\",\"error\":{\"code\":\"auth_failed\"}}");
  ui_hki h;
  SD_CHECK(j != NULL);
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "h", &h), (int)UI_HKI_NONE);
  sd_json_free(j);
  j = parse("{\"mount_id\":\"m\",\"state\":\"mounted\"}");
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "h", &h), (int)UI_HKI_NONE);
  sd_json_free(j);
  /* no host in the error: the host of the mount; no path and no line: empty and zero */
  j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_mismatch\"}}");
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "srv.example", &h), (int)UI_HKI_CHANGED);
  SD_CHECK_STR(h.host, "srv.example");
  SD_CHECK(h.path[0] == 0);
  SD_CHECK_EQ_INT((int)h.line, 0);
  sd_json_free(j);
}

SD_TEST(hkissue_type_unavailable_has_no_types_yet)
{
  sd_json *j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_type_unavailable\",\"detail\":\"x\"}}");
  ui_hki h;
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "srv.example", &h), (int)UI_HKI_TYPE_UNAVAILABLE);
  SD_CHECK_EQ_INT(ui_hki_has_stored_type(&h), 0);
  sd_json_free(j);
  /* a later agent that reports the stored type: the notification names it */
  j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_type_unavailable\",\"stored_type\":\"ssh-rsa\"}}");
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "srv.example", &h), (int)UI_HKI_TYPE_UNAVAILABLE);
  SD_CHECK_EQ_INT(ui_hki_has_stored_type(&h), 1);
  sd_json_free(j);
}

SD_TEST(hkissue_text_is_reduced_to_printable_ascii)
{
  /* a host with a bidi override and a control character, a path with a control character (TM-R09) */
  sd_json *j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_mismatch\","
                     "\"host\":\"a\\u202eb\\u0007c\",\"stored_fp\":\"SHA256:x\\ny\","
                     "\"store_path\":\"C:\\\\k\\u0001h\"}}");
  ui_hki h;
  size_t i;
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, NULL, &h), (int)UI_HKI_CHANGED);
  for (i = 0; h.host[i] != 0; i++)
    SD_CHECK((unsigned char)h.host[i] >= 0x20 && (unsigned char)h.host[i] < 0x7f);
  for (i = 0; h.stored_fp[i] != 0; i++)
    SD_CHECK((unsigned char)h.stored_fp[i] >= 0x20 && (unsigned char)h.stored_fp[i] < 0x7f);
  for (i = 0; h.path[i] != 0; i++)
    SD_CHECK(h.path[i] >= 0x20);
  sd_json_free(j);
}

SD_TEST(hkissue_store_is_told_from_the_path)
{
  const wchar_t *user = L"C:\\Users\\a\\AppData\\Roaming\\LibreStatic\\ShellDrive\\known_hosts";
  SD_CHECK_EQ_INT((int)ui_hki_classify(user, user), (int)UI_HKI_SRC_USER);
  SD_CHECK_EQ_INT((int)ui_hki_classify(L"c:\\users\\a\\appdata\\roaming\\librestatic\\shelldrive\\known_hosts", user),
                  (int)UI_HKI_SRC_USER);
  SD_CHECK_EQ_INT((int)ui_hki_classify(L"C:\\ProgramData\\LibreStatic\\ShellDrive\\known_hosts", user),
                  (int)UI_HKI_SRC_MACHINE);
  SD_CHECK_EQ_INT((int)ui_hki_classify(L"C:\\Users\\a\\.ssh\\known_hosts", user), (int)UI_HKI_SRC_OPENSSH);
  SD_CHECK_EQ_INT((int)ui_hki_classify(L"C:\\Users\\a\\.ssh\\known_hosts2", user), (int)UI_HKI_SRC_OPENSSH);
  SD_CHECK_EQ_INT((int)ui_hki_classify(L"", user), (int)UI_HKI_SRC_PUTTY);
  SD_CHECK_EQ_INT((int)ui_hki_classify(L"Software\\SimonTatham\\PuTTY\\SshHostKeys", user), (int)UI_HKI_SRC_PUTTY);
  SD_CHECK_EQ_INT((int)ui_hki_classify(L"D:\\somewhere\\keys.txt", user), (int)UI_HKI_SRC_FILE);
  SD_CHECK_EQ_INT((int)ui_hki_classify(NULL, NULL), (int)UI_HKI_SRC_PUTTY);
}

SD_TEST(hkissue_what_each_store_offers)
{
  const wchar_t *file = L"C:\\Users\\a\\.ssh\\known_hosts";
  /* only the user store can be fixed in the host key manager; only the live sources can be switched off */
  SD_CHECK_EQ_INT(ui_hki_source_removable_here(UI_HKI_SRC_USER), 1);
  SD_CHECK_EQ_INT(ui_hki_source_removable_here(UI_HKI_SRC_MACHINE), 0);
  SD_CHECK_EQ_INT(ui_hki_source_removable_here(UI_HKI_SRC_OPENSSH), 0);
  SD_CHECK_EQ_INT(ui_hki_source_can_stop(UI_HKI_SRC_OPENSSH), 1);
  SD_CHECK_EQ_INT(ui_hki_source_can_stop(UI_HKI_SRC_PUTTY), 1);
  SD_CHECK_EQ_INT(ui_hki_source_can_stop(UI_HKI_SRC_USER), 0);
  SD_CHECK_EQ_INT(ui_hki_source_can_stop(UI_HKI_SRC_MACHINE), 0);
  SD_CHECK_EQ_INT(ui_hki_source_can_stop(UI_HKI_SRC_FILE), 0);
  /* a file location exists for OpenSSH and other files; the registry has none and ShellDrive's own lists use the manager */
  SD_CHECK_EQ_INT(ui_hki_source_can_open(UI_HKI_SRC_OPENSSH, file), 1);
  SD_CHECK_EQ_INT(ui_hki_source_can_open(UI_HKI_SRC_FILE, file), 1);
  SD_CHECK_EQ_INT(ui_hki_source_can_open(UI_HKI_SRC_PUTTY, file), 0);
  SD_CHECK_EQ_INT(ui_hki_source_can_open(UI_HKI_SRC_USER, file), 0);
  SD_CHECK_EQ_INT(ui_hki_source_can_open(UI_HKI_SRC_OPENSSH, L""), 0);
  /* the wording follows the store */
  SD_CHECK_EQ_INT((int)ui_hki_where_of(UI_HKI_SRC_PUTTY), (int)UI_HKI_WHERE_PUTTY);
  SD_CHECK_EQ_INT((int)ui_hki_where_of(UI_HKI_SRC_OPENSSH), (int)UI_HKI_WHERE_FILE);
  SD_CHECK_EQ_INT((int)ui_hki_todo_of(UI_HKI_SRC_USER), (int)UI_HKI_TODO_USER);
  SD_CHECK_EQ_INT((int)ui_hki_todo_of(UI_HKI_SRC_MACHINE), (int)UI_HKI_TODO_MACHINE);
  SD_CHECK_EQ_INT((int)ui_hki_todo_of(UI_HKI_SRC_PUTTY), (int)UI_HKI_TODO_SOURCE);
}

SD_TEST(hkissue_explorer_arguments_are_safe)
{
  wchar_t out[300];
  SD_CHECK_EQ_INT(ui_hki_select_args(L"C:\\Users\\a\\.ssh\\known_hosts", out, 300), 1);
  SD_CHECK(wcscmp(out, L"/select,\"C:\\Users\\a\\.ssh\\known_hosts\"") == 0);
  SD_CHECK_EQ_INT(ui_hki_select_args(L"\\\\srv\\share\\known_hosts", out, 300), 1);
  /* relative paths, quotes and control characters never reach the command line */
  SD_CHECK_EQ_INT(ui_hki_path_ok(L"known_hosts"), 0);
  SD_CHECK_EQ_INT(ui_hki_path_ok(L"C:\\a\" /x"), 0);
  SD_CHECK_EQ_INT(ui_hki_path_ok(L"C:\\a\nb"), 0);
  SD_CHECK_EQ_INT(ui_hki_path_ok(L"C:"), 0);
  SD_CHECK_EQ_INT(ui_hki_path_ok(NULL), 0);
  /* a buffer that is too small is refused, not truncated */
  SD_CHECK_EQ_INT(ui_hki_select_args(L"C:\\Users\\a\\.ssh\\known_hosts", out, 12), 0);
}
