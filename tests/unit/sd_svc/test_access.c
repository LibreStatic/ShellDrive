/* Pure service rules (apps/shelldrive-host/svc_access.c): the decision table, list resolution, profile refusals,
   the volume SDDL and the identity path rule. No service runs here. */
#include <windows.h>
#include <sddl.h>
#include <string.h>

#include "sd_test.h"
#include "svc_access.h"

static void member(svc_member *m, int in_access, int in_write, int admin)
{
  m->in_access = in_access;
  m->in_write = in_write;
  m->admin_elevated = admin;
}

/* One row per combination the design names (03 §1.3, §2.2, D35). */
SD_TEST(decide_table)
{
  svc_member m;
  svc_rights r;

  /* elevated admin in the list: everything */
  member(&m, 1, 0, 1);
  svc_decide(&m, &r);
  SD_CHECK_EQ_INT(r.see_letter, 1);
  SD_CHECK_EQ_INT(r.see_state, 1);
  SD_CHECK_EQ_INT(r.see_details, 1);
  SD_CHECK_EQ_INT(r.use, 1);
  SD_CHECK_EQ_INT(r.write, 1);        /* BUILTIN\Administrators always gets write (3.4.1) */
  SD_CHECK_EQ_INT(r.manage, 1);

  /* elevated admin not in the list: manages, sees, does not use (D35: no implicit access) */
  member(&m, 0, 0, 1);
  svc_decide(&m, &r);
  SD_CHECK_EQ_INT(r.see_state, 1);
  SD_CHECK_EQ_INT(r.see_details, 1);
  SD_CHECK_EQ_INT(r.use, 0);
  SD_CHECK_EQ_INT(r.write, 0);
  SD_CHECK_EQ_INT(r.manage, 1);

  /* ordinary member, read-only */
  member(&m, 1, 0, 0);
  svc_decide(&m, &r);
  SD_CHECK_EQ_INT(r.see_state, 1);
  SD_CHECK_EQ_INT(r.see_details, 0);
  SD_CHECK_EQ_INT(r.use, 1);
  SD_CHECK_EQ_INT(r.write, 0);
  SD_CHECK_EQ_INT(r.manage, 0);

  /* ordinary member in the write list */
  member(&m, 1, 1, 0);
  svc_decide(&m, &r);
  SD_CHECK_EQ_INT(r.write, 1);
  SD_CHECK_EQ_INT(r.manage, 0);

  /* write list without access (cannot happen after validation, must still be refused) */
  member(&m, 0, 1, 0);
  svc_decide(&m, &r);
  SD_CHECK_EQ_INT(r.use, 0);
  SD_CHECK_EQ_INT(r.write, 0);

  /* outsider: only the letter (TM-R25: "only letter in reserved_letters") */
  member(&m, 0, 0, 0);
  svc_decide(&m, &r);
  SD_CHECK_EQ_INT(r.see_letter, 1);
  SD_CHECK_EQ_INT(r.see_state, 0);
  SD_CHECK_EQ_INT(r.see_details, 0);
  SD_CHECK_EQ_INT(r.use, 0);
  SD_CHECK_EQ_INT(r.write, 0);
  SD_CHECK_EQ_INT(r.manage, 0);
}

/* Name resolver for the tests: two names, anything else fails. */
static int resolve_test(void *ctx, const char *entry, char *out, size_t cap)
{
  (void)ctx;
  if (_stricmp(entry, "Everyone") == 0) { strcpy_s(out, cap, "S-1-1-0"); return 1; }
  if (_stricmp(entry, "BUILTIN\\Administrators") == 0) { strcpy_s(out, cap, "S-1-5-32-544"); return 1; }
  return 0;
}

SD_TEST(acl_resolves_names_and_fails_closed)
{
  sd_profile p;
  svc_acl acl;
  sd_profile_defaults(&p);
  p.scope = SD_PROFILE_SCOPE_SERVICE;
  strcpy_s(p.service_access, sizeof(p.service_access), "Everyone, S-1-5-32-544 ,BUILTIN\\Administrators, Everyone");
  strcpy_s(p.service_access_write, sizeof(p.service_access_write), "BUILTIN\\Administrators");
  SD_CHECK_EQ_INT(svc_acl_build(&p, resolve_test, NULL, &acl), SD_OK);
  SD_CHECK_EQ_INT(acl.n_access, 2);     /* duplicates collapse, the explicit SID and the name are the same entry */
  SD_CHECK_EQ_INT(acl.n_write, 1);
  SD_CHECK_STR(acl.write[0], "S-1-5-32-544");

  /* an unresolved name is a refusal, never a silently smaller list */
  strcpy_s(p.service_access, sizeof(p.service_access), "Nobody-Here");
  SD_CHECK_EQ_INT(svc_acl_build(&p, resolve_test, NULL, &acl), SD_E_NOT_FOUND);

  /* a write entry outside the access list is refused (03 §3.4.1 subset rule) */
  strcpy_s(p.service_access, sizeof(p.service_access), "Everyone");
  strcpy_s(p.service_access_write, sizeof(p.service_access_write), "S-1-5-32-544");
  SD_CHECK_EQ_INT(svc_acl_build(&p, resolve_test, NULL, &acl), SD_E_INVALID_PARAM);
}

static sd_profile good_profile(void)
{
  sd_profile p;
  sd_profile_defaults(&p);
  p.scope = SD_PROFILE_SCOPE_SERVICE;
  strcpy_s(p.id, sizeof(p.id), "0123456789abcdef0123456789abcdef");
  strcpy_s(p.name, sizeof(p.name), "Shared");
  strcpy_s(p.host, sizeof(p.host), "files.example");
  strcpy_s(p.user, sizeof(p.user), "svc");
  strcpy_s(p.service_access, sizeof(p.service_access), "Everyone");
  p.auth_methods = SD_PROFILE_AUTH_PUBLICKEY | SD_PROFILE_AUTH_PASSWORD;
  p.agent = SD_PROFILE_AGENT_AUTO;
  p.backend = SD_PROFILE_BACKEND_AUTO;
  return p;
}

SD_TEST(validate_profile_refusals)
{
  sd_profile p = good_profile();
  const char *key = NULL, *why = NULL;
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_OK);
  SD_CHECK(key == NULL);

  p.scope = SD_PROFILE_SCOPE_USER;
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_E_INVALID_PARAM);
  SD_CHECK_STR(key, "profile.scope");
  p.scope = SD_PROFILE_SCOPE_SERVICE;

  /* D17: agents are refused for service profiles (pageant and openssh explicitly; auto means none here) */
  p.agent = SD_PROFILE_AGENT_PAGEANT;
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_E_INVALID_PARAM);
  SD_CHECK_STR(key, "auth.agent");
  p.agent = SD_PROFILE_AGENT_OPENSSH;
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_E_INVALID_PARAM);
  p.agent = SD_PROFILE_AGENT_NONE;
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_OK);
  p.agent = SD_PROFILE_AGENT_AUTO;

  /* 2.6: keyboard-interactive needs a console user */
  p.auth_methods |= SD_PROFILE_AUTH_KBDINT;
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_E_INVALID_PARAM);
  SD_CHECK_STR(key, "auth.methods");
  p.auth_methods &= ~SD_PROFILE_AUTH_KBDINT;

  /* no current user exists in the service: the user is explicit */
  strcpy_s(p.user, sizeof(p.user), "");
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_E_INVALID_PARAM);
  SD_CHECK_STR(key, "profile.user");
  strcpy_s(p.user, sizeof(p.user), "svc");

  /* not in this build: jump hosts, proxies, global WebDAV (D11) */
  strcpy_s(p.jump, sizeof(p.jump), "bastion");
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_E_INVALID_PARAM);
  SD_CHECK_STR(key, "proxy.jump");
  p.jump[0] = 0;
  p.backend = SD_PROFILE_BACKEND_WEBDAV;
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_E_INVALID_PARAM);
  SD_CHECK_STR(key, "mount.backend");
  p.backend = SD_PROFILE_BACKEND_AUTO;

  /* D35: no service_access, no drive */
  p.service_access[0] = 0;
  SD_CHECK_EQ_INT(svc_validate_profile(&p, &key, &why), SD_E_INVALID_PARAM);
  SD_CHECK_STR(key, "profile.service_access");
}

SD_TEST(volume_sddl_is_valid_and_lists_every_entry)
{
  svc_acl acl;
  char sddl[1024];
  PSECURITY_DESCRIPTOR sd = NULL;
  ULONG len = 0;
  BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
  PACL dacl = NULL;
  memset(&acl, 0, sizeof(acl));
  acl.n_access = 2;
  strcpy_s(acl.access[0], SVC_SID_MAX, "S-1-5-32-545");   /* Users */
  strcpy_s(acl.access[1], SVC_SID_MAX, "S-1-1-0");       /* Everyone */
  acl.n_write = 1;
  strcpy_s(acl.write[0], SVC_SID_MAX, "S-1-1-0");
  SD_CHECK_EQ_INT(svc_volume_sddl(&acl, sddl, sizeof(sddl)), SD_OK);
  SD_CHECK(strstr(sddl, "(A;OICI;FRFX;;;S-1-5-32-545)") != NULL);
  SD_CHECK(strstr(sddl, "(A;OICI;FA;;;S-1-1-0)") != NULL);
  SD_CHECK(strstr(sddl, "(A;OICI;FA;;;BA)") != NULL);   /* admins always: volume control, vfs check (3.4.1) */
  /* the SDDL must parse (the Dokany volume descriptor is self-relative and built from it) */
  {
    wchar_t wsddl[1024];
    int i;
    for (i = 0; sddl[i] && i < 1023; i++) wsddl[i] = (wchar_t)(unsigned char)sddl[i];
    wsddl[i] = 0;
    SD_CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(wsddl, SDDL_REVISION_1, &sd, &len) != 0);
    if (sd) {
      SD_CHECK(GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted) != 0);
      SD_CHECK(dacl_present);
      LocalFree(sd);
    }
  }
  SD_CHECK_EQ_INT(svc_volume_sddl(&acl, sddl, 20), SD_E_NO_SPACE);
}

SD_TEST(identity_path_must_stay_under_the_service_folder)
{
  SD_CHECK(svc_path_under(L"C:\\PD\\LibreStatic\\ShellDrive\\service\\keys\\a.ppk", L"C:\\PD\\LibreStatic\\ShellDrive\\service"));
  SD_CHECK(!svc_path_under(L"C:\\PD\\LibreStatic\\ShellDrive\\service", L"C:\\PD\\LibreStatic\\ShellDrive\\service"));
  SD_CHECK(!svc_path_under(L"C:\\PD\\LibreStatic\\ShellDrive\\service2\\a.ppk", L"C:\\PD\\LibreStatic\\ShellDrive\\service"));
  SD_CHECK(!svc_path_under(L"C:\\Users\\me\\key.ppk", L"C:\\PD\\LibreStatic\\ShellDrive\\service"));
  SD_CHECK(!svc_path_under(L"C:\\PD\\LibreStatic\\ShellDrive\\service\\..\\..\\Users\\me\\k.ppk",
                           L"C:\\PD\\LibreStatic\\ShellDrive\\service"));
  SD_CHECK(!svc_path_under(L"C:\\PD\\LibreStatic\\ShellDrive\\service\\x\\..", L"C:\\PD\\LibreStatic\\ShellDrive\\service"));
  SD_CHECK(!svc_path_under(L"C:\\PD\\LibreStatic\\ShellDrive\\service/a.ppk", L"C:\\PD\\LibreStatic\\ShellDrive\\service"));
}
