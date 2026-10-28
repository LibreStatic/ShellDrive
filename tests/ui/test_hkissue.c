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

SD_TEST(hkissue_type_unavailable_lists_stored_and_offered_types)
{
  static const char ev[] =
      "{\"mount_id\":\"m-7\",\"state\":\"failed\",\"error\":{\"code\":\"host_key_type_unavailable\",\"detail\":\"d\","
      "\"exit_code\":6,\"host\":\"example.org\",\"lookup_name\":\"[example.org]:2222\","
      "\"stored_type\":\"ssh-ed25519,ssh-rsa\",\"stored_types\":[\"ssh-ed25519\",\"ssh-rsa\"],"
      "\"offered_types\":[\"ecdsa-sha2-nistp256\",\"\",\"rsa-sha2-512\"],"
      "\"offered_type\":\"ecdsa-sha2-nistp256\",\"offered_fp\":\"SHA256:abc\"}}";
  sd_json *j = parse(ev);
  ui_hki h;
  char list[200];
  SD_CHECK(j != NULL);
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "other", &h), (int)UI_HKI_TYPE_UNAVAILABLE);
  SD_CHECK_STR(h.host, "example.org");
  SD_CHECK_STR(h.lookup_name, "[example.org]:2222");
  SD_CHECK_EQ_INT((int)h.n_stored, 2);
  SD_CHECK_EQ_INT((int)h.n_offered, 2);              /* the empty name is skipped */
  SD_CHECK_EQ_INT((int)ui_hki_stored_list(&h, list, sizeof(list)), 2);
  SD_CHECK_STR(list, "ssh-ed25519, ssh-rsa");
  SD_CHECK_EQ_INT((int)ui_hki_offered_list(&h, list, sizeof(list)), 2);
  SD_CHECK_STR(list, "ecdsa-sha2-nistp256, rsa-sha2-512");
  SD_CHECK_EQ_INT(ui_hki_has_offered_key(&h), 1);
  SD_CHECK_STR(h.offered_fp, "SHA256:abc");
  SD_CHECK_EQ_INT(ui_hki_has_stored_type(&h), 1);
  /* "Add key from server" starts with the name the key was looked up under */
  SD_CHECK_STR(ui_hki_add_target(&h), "[example.org]:2222");
  sd_json_free(j);
}

SD_TEST(hkissue_type_unavailable_without_offered_key_or_arrays)
{
  /* the server presented no key: no offered_type; an agent that sends only the comma-joined stored_type */
  sd_json *j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_type_unavailable\","
                     "\"host\":\"h.example\",\"stored_type\":\"ssh-rsa, ssh-ed25519\",\"offered_types\":[]}}");
  ui_hki h;
  char list[100];
  SD_CHECK(j != NULL);
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, NULL, &h), (int)UI_HKI_TYPE_UNAVAILABLE);
  SD_CHECK_EQ_INT(ui_hki_has_offered_key(&h), 0);
  SD_CHECK_EQ_INT((int)h.n_offered, 0);
  SD_CHECK_EQ_INT((int)h.n_stored, 2);
  SD_CHECK_EQ_INT((int)ui_hki_stored_list(&h, list, sizeof(list)), 2);
  SD_CHECK_STR(list, "ssh-rsa, ssh-ed25519");
  SD_CHECK_EQ_INT((int)ui_hki_offered_list(&h, list, sizeof(list)), 0);
  SD_CHECK_STR(list, "");
  SD_CHECK_STR(ui_hki_add_target(&h), "h.example");   /* no lookup_name: the host */
  /* a list that does not fit is cut at a whole name */
  SD_CHECK_EQ_INT((int)ui_hki_stored_list(&h, list, 12), 1);
  SD_CHECK_STR(list, "ssh-rsa");
  sd_json_free(j);
}

SD_TEST(hkissue_names_are_reduced_to_printable_ascii_and_capped)
{
  sd_json *j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_type_unavailable\","
                     "\"stored_types\":[\"ssh-\\u202eed\\u0007\"],\"offered_types\":[\"a\",\"b\",\"c\",\"d\",\"e\",\"f\","
                     "\"g\",\"h\",\"i\",\"j\",\"k\",\"l\",\"m\",\"n\",\"o\",\"p\",\"q\",\"r\"]}}");
  ui_hki h;
  size_t i;
  SD_CHECK(j != NULL);
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, NULL, &h), (int)UI_HKI_TYPE_UNAVAILABLE);
  for (i = 0; h.stored_types[0][i] != 0; i++)
    SD_CHECK((unsigned char)h.stored_types[0][i] >= 0x20 && (unsigned char)h.stored_types[0][i] < 0x7f);
  SD_CHECK_EQ_INT((int)h.n_offered, UI_HKI_OFFERED_MAX);   /* 18 sent, 16 kept */
  sd_json_free(j);
}

SD_TEST(hkissue_store_kind_decides_the_source)
{
  const wchar_t *user = L"C:\\Users\\a\\AppData\\Roaming\\LibreStatic\\ShellDrive\\known_hosts";
  sd_json *j;
  ui_hki h;
  /* store_kind wins over the path, which says OpenSSH here */
  j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_mismatch\",\"store_kind\":\"machine\","
            "\"store_path\":\"C:\\\\Users\\\\a\\\\.ssh\\\\known_hosts\"}}");
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "h", &h), (int)UI_HKI_CHANGED);
  SD_CHECK_EQ_INT((int)h.store, (int)UI_HKI_STORE_MACHINE);
  SD_CHECK_EQ_INT((int)ui_hki_source_of(&h, user), (int)UI_HKI_SRC_MACHINE);
  sd_json_free(j);
  j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_mismatch\",\"store_kind\":\"user\"}}");
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "h", &h), (int)UI_HKI_CHANGED);
  SD_CHECK_EQ_INT((int)ui_hki_source_of(&h, user), (int)UI_HKI_SRC_USER);   /* no path needed */
  sd_json_free(j);
  j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_mismatch\",\"store_kind\":\"putty\","
            "\"store_path\":\"\",\"store_line\":0}}");
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "h", &h), (int)UI_HKI_CHANGED);
  SD_CHECK_EQ_INT((int)ui_hki_source_of(&h, user), (int)UI_HKI_SRC_PUTTY);
  sd_json_free(j);
  j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_mismatch\",\"store_kind\":\"openssh\","
            "\"store_path\":\"D:\\\\keys\\\\kh\"}}");
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "h", &h), (int)UI_HKI_CHANGED);
  SD_CHECK_EQ_INT((int)ui_hki_source_of(&h, user), (int)UI_HKI_SRC_OPENSSH);   /* a path that classify would call a file */
  sd_json_free(j);
  /* an unknown token and an agent without store_kind fall back to the path */
  j = parse("{\"mount_id\":\"m\",\"error\":{\"code\":\"host_key_mismatch\",\"store_kind\":\"floppy\","
            "\"store_path\":\"C:\\\\Users\\\\a\\\\.ssh\\\\known_hosts\"}}");
  SD_CHECK_EQ_INT((int)ui_hki_parse(j, "h", &h), (int)UI_HKI_CHANGED);
  SD_CHECK_EQ_INT((int)h.store, (int)UI_HKI_STORE_UNKNOWN);
  SD_CHECK_EQ_INT((int)ui_hki_source_of(&h, user), (int)UI_HKI_SRC_OPENSSH);
  sd_json_free(j);
}
