# 02 — Filesystem layer: `sd_vfs`, `sd_webdav`, `sd_dokan`

Status: design, updated with the accepted decisions in `decisions.md` (D1–D32) and the resolutions of
`00-integration-review.md` (C1–C46, R1–R18, threading rules §4.1). Where this document and `decisions.md`
differ, `decisions.md` wins. Scope: the backend-agnostic filesystem core (`sd_vfs`), the local WebDAV server
for the built-in Windows redirector (`sd_webdav`), and the Dokany adapter (`sd_dokan`). The SFTP client
(`sd_sftp`, document 01) is designed elsewhere; section 9 lists what this layer needs from it and how each
item was resolved. The host-side orchestration (profile → connections → `sd_vfs` → backend) is `sd_mount`
(owner: 03); this document states what `sd_mount` passes in.

Conventions: "MUST/SHOULD" are normative. "Verify:" marks a platform fact that could not be confirmed
from a primary source and must be checked on the test matrix before release. Sources are cited inline.
Names of `sd_sftp` types, errors and states (`sd_err`, `SD_E_*`, `SD_SFTP_ST_*`) are 01's and canonical
(C13). Profile key names are owned by 03's profile schema table (C46); the names used here are the keys
`sd_vfs` consumes.

---

## 0. Summary of decisions

| # | Decision |
|---|----------|
Local decision ids (FS-n) are this document's own; `D<n>` without prefix refers to `decisions.md`.

| # | Decision |
|---|----------|
| FS-1 | One `sd_vfs` instance per mount. It owns path mapping, node/handle tables, caches, read-ahead, write modes, reconnect, connection-pool scheduling and error mapping. Backends are thin protocol adapters. |
| FS-2 | Internal status codes are a small `sd_vfs_status` enum. `sd_err` (01) maps to it through one table in `sd_vfs` (C13); each backend has one mapping table (to NTSTATUS for Dokany, to HTTP for WebDAV). This document's NTSTATUS/HTTP tables are normative (C24). |
| FS-3 | Case-insensitive, case-preserving view by default. Exact-case match wins; case collisions on case-sensitive remotes are disambiguated with a deterministic `~cN` suffix (section 1.3). |
| FS-4 | Remote names are bytes. Stage 1 is 01's lossless `sd_name_to_wide`/`sd_name_from_wide` (invalid UTF-8 → U+F780..U+F7FF, bijective). Stage 2, per component, maps characters illegal on Windows and a trailing dot/space to U+F000+ch (Cygwin convention) (C23). |
| FS-5 | Close-to-open consistency (NFS model): attributes are revalidated on open-for-data if older than 1 s; data cache is keyed by (size, mtime) validators. |
| FS-6 | **Write mode per profile (D9). Default `write_mode = through`**: every write is acknowledged by the server before it completes for the application. `write_mode = behind` is opt-in: bounded window (16 MiB per node, 64 MiB per mount), sticky errors, 60 s grace retransmit, and an always-on `write_failed` notification (C45). In both modes cleanup drains synchronously and `FlushFileBuffers` drains and sends `fsync@openssh.com` (section 4.4). |
| FS-7 | Writes fail fast while disconnected (`SD_VFS_E_DISCONNECTED` → `STATUS_CONNECTION_DISCONNECTED` / HTTP 503). Reads are served from cache when valid. No offline write queue. Only in write-behind mode are accepted-but-unacknowledged writes retransmitted, if the connection returns within the grace window and the remote file is unchanged. |
| FS-8 | Symlinks: `follow` (default) or `hide` (D12, amendment A3). Reparse-point exposure is **postponed** until after 1.0 (unmodified Dokany 2.x has no FSCTL callback; a self-built Dokany fork was rejected). The profile value `reparse` is reserved and rejected (section 6.9). |
| FS-9 | WebDAV security: bind 127.0.0.1 and ::1 only, random port, 130-bit path token per mount, **plus** Negotiate/NTLM verification over loopback via SSPI of the caller's SID (owner for per-user servers, allowed group for the service server). No Basic, no `BasicAuthLevel` change (C26, amendment A2). |
| FS-10 | WebDAV is addressed as `localhost` (dotless name, so WinHTTP treats it as intranet and sends default credentials automatically; [KB 943280](https://support.microsoft.com/kb/943280/)). |
| FS-11 | Dokany: `dokan2.dll` loaded dynamically from `%SystemRoot%\System32` by full path; minimum library and driver version **2.1.0** (option flag values were renumbered in 2.1.0), bundled/recommended **2.3.1**. Redistributed unmodified per D32 / 04 §7 (section 6.1). Volume FS name `NTFS` by default, configurable (D23). |
| FS-12 | Dokany per-user mounts use `DOKAN_OPTION_CURRENT_SESSION` and `DOKAN_OPTION_NETWORK` (when the Dokany network provider is installed); global mounts come from the service without `CURRENT_SESSION`. Every create checks the requestor token. |
| FS-13 | Backend `auto`: Dokany when OS >= Win7 SP1, native arch in {x86, x64, ARM64}, and a compatible Dokany is installed; WebDAV otherwise. A forced backend never silently falls back. |
| FS-14 | Global drives: **Dokany is the primary path** and the only one that is guaranteed before logon. Global WebDAV drives are **attempted** (D11): the service hosts the WebDAV server and makes one system-wide mapping, decided per OS by a lab go/no-go spike early in M5. Where the spike fails, that OS falls back to a per-user attach of the service-hosted server at logon (section 7.7). |
| FS-15 | Connections (D18, D19): a mount uses **one `sd_sftp_session`** whose pool holds 1–4 SSH connections (default 1). The primary connection carries a metadata and a bulk SFTP channel (auto-degrade to one); extra connections open one bulk channel only. Metadata stays on the primary; `sd_vfs` opts large sequential handles into striping with `SD_SFTP_O_STRIPED`, and `sd_sftp` routes, stripes and reconnects per connection (01 §10.9; section 5.6). |
| FS-16 | Remote identity (D10): no exec by default. Our uid comes from the owner of the home directory, confirmed by the first file we create; `identity_probe = exec` is an opt-in (section 3.4). |
| FS-17 | `sd_sftp` refines `SSH_FX_FAILURE` (01 `SD_SFTP_OPT_REFINE_ERRORS`); `sd_vfs` does no extra probes (C14). Every vfs operation runs under a deadline below the backend's own timeout, and `sd_sftp` checks liveness on any request timeout (C16, section 5.7). |

---

## 1. `sd_vfs` — path model

### 1.1 Paths

- **Mount root**: a remote absolute path, resolved once per connection with `realpath` (default `.` = home).
  Stored as bytes.
- **Internal path** (`vpath`): UTF-8 bytes relative to the mount root, `/`-separated, no `.`/`..`,
  no leading or trailing `/`. The root is the empty string. Remote path = `root + "/" + vpath`.
- **Windows path**: UTF-16, `\`-separated, as given by Dokany (`\dir\file`) or decoded from a WebDAV URL
  (percent-decoded UTF-8, then converted to UTF-16 to go through the same mapping).
- `..` in Windows input is resolved lexically and may not climb above the root (`SD_VFS_E_INVALID_NAME`).
- Stream syntax (`file:stream`) is rejected (`SD_VFS_E_INVALID_NAME`). We do not set `DOKAN_OPTION_ALT_STREAM`.
  Browsers that write `Zone.Identifier` streams tolerate failure, as they do on FAT32.

### 1.2 Name encoding (remote bytes ↔ Windows UTF-16)

Two stages (C23). Remote → Windows, per component:

1. **Stage 1 (01 §10.7, `sd_name_to_wide`)**: decode as UTF-8. Each byte that is not part of a valid
   sequence maps to U+F700+byte (U+F780..U+F7FF). A *valid* sequence that encodes a code point in
   U+F780..U+F7FF is also escaped byte-wise, so stage 1 is a bijection on byte strings. Code points are not
   normalized (macOS NFD names stay NFD).
2. **Stage 2 (`sd_vfs`)**: characters illegal in Win32 names `\ : * ? " < > |` and control characters
   U+0001..U+001F map to U+F000+ch. This is the Cygwin/MSYS convention, so files shared with those tools
   keep the same names. A trailing space or dot maps to U+F020 / U+F02E.
3. Reserved device names (`CON`, `NUL`, `COM1`...) are left as is. They are reachable via `\\?\` paths
   only; this is a documented limitation.

Windows → remote is the exact inverse (stage 2 inverse, then `sd_name_from_wide`). A Windows name that
contains a character in U+F000..U+F07F is decoded back to the original ASCII character; there is no escape
for a real PUA character in that range in a remote name (rare; documented). The U+F780..U+F7FF range is
lossless thanks to stage 1.

Optional per-profile `remote_charset` (a Windows code page, e.g. 1252) for legacy servers. When set, it
replaces **stage 1 only** (`MultiByteToWideChar` / `WideCharToMultiByte` with that code page); stage 2 is
unchanged.

Names longer than 255 UTF-16 units are listed but cannot be opened from Win32 (`MaximumComponentLength`
is reported as 255).

### 1.3 Case sensitivity

Windows callers expect case-insensitive, case-preserving semantics. Remotes are usually case-sensitive
(Linux, BSD) but can be case-insensitive (macOS APFS by default, Windows OpenSSH server).

**Remote case detection** at mount (cached per connection generation of the primary connection): if the
server identity reports the `OpenSSH_for_Windows` quirk flag (R12), assume insensitive. Otherwise `lstat` the mount root's last path component with
its case inverted. If that succeeds and returns the same attributes, the remote is insensitive.
An explicit profile option `remote_case = sensitive|insensitive|auto` overrides this.

**View mode** (profile option `case = insensitive|sensitive`, default `insensitive`). `sensitive` is
Dokany-only (`DOKAN_OPTION_CASE_SENSITIVE`) and skips everything below.

**Lookup key**: the component upper-cased with `LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE)` (XP+).
This is close to the NTFS upcase table; exact parity for exotic scripts is not required.

**Lookup strategy** for one component under a parent node:

1. If the parent's directory listing is cached and fresh: exact-case match, then folded-key match.
2. Otherwise `lstat` the exact-case path (1 RTT). This is the common case.
3. If that fails with "no such file" and the remote is case-sensitive: fetch the parent listing
   (single-flight per directory), then go back to step 1. If still not found: negative entry.
4. On a case-insensitive remote, step 2 is final.

**Creates** (`FILE_CREATE`, `FILE_OPEN_IF`, `FILE_OVERWRITE_IF`, `FILE_SUPERSEDE`, `MKCOL`, rename target)
on a case-sensitive remote MUST check for a case-insensitive collision first. This uses the parent
listing (fetched if not fresh), costing one extra RTT on cold directories. An existing `README` makes a
create of `Readme` return `SD_VFS_E_EXISTS` (or open `README` for `OPEN_IF`), like NTFS.

**Collisions** (`README` and `readme` in one directory of a case-sensitive remote). Dokany's kernel FCB
table is case-insensitive in the default mode, so two names that fold the same would share one FCB and
corrupt each other. Policy:
- Sort the colliding entries by raw byte order. The first keeps its name; the others are exposed as
  `<stem>~c<N><ext>` (N = 2, 3, ...; `<ext>` is the last `.xxx`, if any). If the mangled name itself
  exists, N increases.
- The mangled-to-real mapping lives in the directory node and is rebuilt on every listing refresh.
  Mangled names are stable while the directory's colliding set is unchanged.
- Mangled entries carry no special attribute. A log line is written once per directory.
- In `sensitive` view mode no mangling happens.

### 1.4 Nodes and the node table

A **node** represents one remote object seen through this mount. It is the unit of caching, locking and
share-mode state. Handles point to nodes, not paths, so renames of open files just move nodes.

```c
/* sd_vfs_internal.h (sketch) */
typedef struct sd_node {
    struct sd_node   *parent;          /* NULL for root */
    sd_bytes          name;            /* remote component bytes */
    WCHAR            *wname;           /* Windows display name (after mapping/mangling) */
    UINT32            key_hash;        /* hash of folded wname, for parent's child table */
    UINT64            file_id;         /* stable per mount: counter assigned at first sight */
    LONG              refs;            /* handles + cache pins + children */
    CRITICAL_SECTION  lock;            /* protects everything below */
    sd_vfs_attr       attr;            /* cached attributes */
    UINT64            attr_time;       /* GetTickCount64-equivalent (own 64-bit tick on XP) */
    UINT32            flags;           /* NEGATIVE, DIR_COMPLETE, DELETE_PENDING, DIRTY, SYMLINK... */
    sd_dirlist       *children;        /* NULL unless listing cached */
    UINT64            dir_time;
    sd_share_state    share;           /* section 2.3 */
    sd_remote_fh      rd, wr;          /* lazily opened remote handles (sd_sftp_file *), each with the
                                          generation it was opened in; refcounted (2.1). Pool
                                          sub-handles of striped files live inside sd_sftp (5.6) */
    sd_wq             *wq;             /* write queue: in-flight and (write-behind) dirty extents (4.4) */
    sd_validator      data_validator;  /* size + mtime the cached data belongs to */
} sd_node;
```

- Nodes are interned in a per-mount hash table keyed by (parent, folded key) and reachable from parents.
- Unreferenced nodes stay as cache entries, LRU-evicted when the node count exceeds `max_nodes`
  (default 200,000, about 40 MB).
- `file_id` is a 64-bit counter. It is reported as the file index (Dokany) and is stable while the node
  is cached. It is not stable across restarts; Windows tools only rely on it within a session.

### 1.5 Attributes

`sd_vfs_attr` is backend-neutral:

```c
typedef struct sd_vfs_attr {
    UINT32  valid;         /* SD_ATTR_SIZE | SD_ATTR_MODE | SD_ATTR_UIDGID | SD_ATTR_TIMES */
    UINT64  size;
    UINT32  mode;          /* POSIX st_mode incl. S_IFMT */
    UINT32  uid, gid;
    INT64   atime, mtime;  /* Unix seconds (SFTP v3 is 32-bit unsigned; widened) */
    INT64   btime;         /* creation time if known, else = mtime */
    UINT32  win_attrs;     /* derived, see 3.1 */
} sd_vfs_attr;
```

---

## 2. `sd_vfs` — handles, opens, share modes, delete, rename

### 2.1 Handle table

```c
typedef struct sd_vfs_handle {
    sd_node    *node;
    UINT32      access;        /* SD_ACC_READ_DATA | WRITE_DATA | APPEND | DELETE | READ_ATTR | WRITE_ATTR ... */
    UINT32      share;         /* FILE_SHARE_* */
    UINT32      opts;          /* DELETE_ON_CLOSE, WRITE_THROUGH, NO_BUFFERING, SEQUENTIAL, RANDOM */
    UINT64      ra_next;       /* read-ahead: expected next offset */
    UINT32      ra_window;     /* current read-ahead window */
    FILETIME    pending_times[3]; UINT32 pending_times_mask;  /* SetFileTime deferred to close */
    UINT32      flags;         /* CLEANED_UP, FAILED, DIR_ENUM_SNAPSHOT */
    sd_dirsnap *enum_snapshot; /* directory enumeration snapshot */
} sd_vfs_handle;
```

- Backends own the storage slot: Dokany stores the pointer in `DOKAN_FILE_INFO.Context`; WebDAV opens a
  handle per request.
- **Lazy remote open.** Opening a local handle does not open a remote handle. Most Windows opens only want
  attributes (Explorer, AV, shell extensions). A remote `SSH_FXP_OPEN` happens on the first read or write.
  The handle goes on the node (`rd` or `wr`; `sd_sftp` binds it to the primary connection's bulk
  channel, and a handle opened with `SD_SFTP_O_STRIPED` gets its pool sub-handles inside `sd_sftp`, 5.6)
  and is shared by all local handles of that node with compatible mode. It is closed when the last local handle needing it is closed.
  Exceptions that open remotely at create time: `FILE_CREATE` and any disposition that may create or
  truncate. These need the remote to decide the outcome atomically.
- Directories never hold a remote handle. Enumeration does `opendir` / `readdir`* / `close` in one go,
  fills the listing cache, and gives the enumerating handle a snapshot.

### 2.2 Create dispositions

Kernel dispositions (Dokany passes these; WebDAV methods map to them) and their SFTP v3 implementation.
The case-collision check (1.3) runs first.

| Disposition | Exists | Does not exist | SFTP |
|---|---|---|---|
| `FILE_SUPERSEDE` (0) | truncate, reset attrs → `SUPERSEDED` | create | `OPEN(WRITE\|CREAT\|TRUNC)` |
| `FILE_OPEN` (1) | open | `OBJECT_NAME_NOT_FOUND` | none (lazy) |
| `FILE_CREATE` (2) | `OBJECT_NAME_COLLISION` | create | `OPEN(WRITE\|CREAT\|EXCL)` |
| `FILE_OPEN_IF` (3) | open (Dokany: return `STATUS_OBJECT_NAME_COLLISION` for "opened existing") | create | `OPEN(WRITE\|CREAT)` if not known to exist |
| `FILE_OVERWRITE` (4) | truncate | `OBJECT_NAME_NOT_FOUND` | `OPEN(WRITE\|TRUNC)` |
| `FILE_OVERWRITE_IF` (5) | truncate (Dokany: `STATUS_OBJECT_NAME_COLLISION`) | create | `OPEN(WRITE\|CREAT\|TRUNC)` |

- A missing parent → `SD_VFS_E_PATH_NOT_FOUND` (`STATUS_OBJECT_PATH_NOT_FOUND`).
- `FILE_DIRECTORY_FILE` + create → `MKDIR` (mode `0777 & ~umask`). `FILE_DIRECTORY_FILE` on a file →
  `NOT_A_DIRECTORY`. `FILE_NON_DIRECTORY_FILE` on a directory → `FILE_IS_A_DIRECTORY`.
- New files get `0666 & ~umask` (profile `umask`, default `022`). With `FILE_ATTRIBUTE_READONLY` they get
  `0444 & ~umask`, applied by `fsetstat` after creation so the creator can still write through its handle.
- `FILE_SUPERSEDE` / overwrite of an existing file keeps its mode (SFTP `TRUNC` keeps the inode).
- On a read-only mount every create, truncate or write access returns `SD_VFS_E_READ_ONLY`
  (`STATUS_MEDIA_WRITE_PROTECTED`). Plain opens with write access are rejected at create, not at first write.
- Append access only (`FILE_APPEND_DATA` without `FILE_WRITE_DATA`): writes go to the cached EOF.
  `SSH_FXF_APPEND` is not used because OpenSSH ignores the offset anyway, and we need to know the
  resulting offset for the cache.

### 2.3 Share-mode emulation

SFTP has no share modes or locks. `sd_vfs` enforces NT share semantics **among local opens** in this
process. A per-process registry keyed by (host key fingerprint, remote absolute path) lets two mounts of
the same remote tree, or a Dokany and a WebDAV mount, see each other.

- The algorithm is `IoCheckShareAccess`'s: counters `open, readers, writers, deleters, shared_read,
  shared_write, shared_delete` per node, checked and updated atomically under `node.lock`. Only data and
  delete access participate. `FILE_READ_ATTRIBUTES`-only opens never conflict (NT semantics).
- Dokany 2.x may also enforce share access in the kernel. Verify: if it does, the vfs check is redundant
  but harmless (same algorithm, same outcome). WebDAV gets real enforcement only from the vfs, and only
  per request. The redirector does its own per-client sharing on top.
- Other remote clients are invisible. This is inherent and documented.
- Byte-range locks (`LockFile`): Dokany handles them in the kernel (we do not set
  `DOKAN_OPTION_FILELOCK_USER_MODE`). They are local-only.

### 2.4 Delete and delete-on-close

NT semantics: deletion takes effect when the last handle closes. Until then new opens fail with
`STATUS_DELETE_PENDING` and the name stays visible.

- A delete request (Dokany `DeleteFile` / `DeleteDirectory` callback on `FileDispositionInformation`, or
  `FILE_DELETE_ON_CLOSE`) **validates only**. It checks the read-only mount and the read-only attribute
  (`STATUS_CANNOT_DELETE`). For directories it checks emptiness against a fresh listing
  (`STATUS_DIRECTORY_NOT_EMPTY`). Then it sets `node.flags |= DELETE_PENDING`.
- Dokany 2.3.0 changed delete semantics to match Microsoft's model and renamed
  `DOKAN_FILE_INFO.DeleteOnClose` to `DeletePending` ([v2.3.0.1000 release notes](https://github.com/dokan-dev/dokany/releases)).
  `sd_dokan` deletes in `Cleanup` when `DeletePending` is set. Older 2.1/2.2 libraries use the same byte
  under the old name; `sd_dokan` reads it the same way.
- At the last cleanup of a `DELETE_PENDING` node, the vfs discards dirty data, closes remote handles and
  sends `REMOVE` or `RMDIR`. Failure (e.g. permission) is logged and raised through the vfs event
  callback (`SD_VFS_EV_DELETE_FAILED`, section 8), which the host turns into a notification, because
  `Cleanup` cannot return a status. The node becomes negative and the parent listing is updated.
- WebDAV `DELETE` is immediate: validate, remove, done. For collections it is recursive depth-first
  (RFC 4918 §9.6.1) and returns 207 with per-member errors on partial failure.
- Hard deletes only. No recycle bin (section 6.6).

### 2.5 Rename

`MoveFileEx` semantics map to two SFTP primitives:

| Request | SFTP | Notes |
|---|---|---|
| no replace | `SSH_FXP_RENAME` | OpenSSH implements v3 RENAME as link+unlink (or stat+rename where links are unsupported), so it fails when the target exists. That gives atomic no-replace for files. |
| replace | `posix-rename@openssh.com` | atomic `rename(2)`. |
| replace, no `posix-rename` | `REMOVE` target then `RENAME` | not atomic; logged once per mount. |
| directory replace | `ENOTEMPTY` from server → `STATUS_ACCESS_DENIED` (NTFS returns this for non-empty directory targets). | |
| case-only (`a.txt` → `A.txt`) | case-sensitive remote: plain `RENAME`. Case-insensitive remote: `RENAME` to `.<name>.sd-<rand>`, then to the final name. | the target "exists" as the same file. |

- The target goes through the collision check. Renaming onto an open target with replace requires that
  the target has no open handles without `FILE_SHARE_DELETE` (NT rule) → `STATUS_ACCESS_DENIED`.
- Renaming an open file or directory is allowed if all its opens share delete (NT rule). On success the
  node subtree moves in the node table (parent pointer and name swap under both parents' locks, taken in
  address order). Open handles keep working. Remote SFTP handles stay valid because POSIX handles are
  inode-based.
- In-flight and dirty write data of the moved node is unaffected (it is node-bound, and remote handles
  and their pool sub-handles are inode-based on every connection), so writes on any connection may complete before or after
  the rename without effect on the result.
- The source and target parent listings are updated in place; they are not dropped.

---

## 3. Attribute, time and security mapping

### 3.1 POSIX → Windows attributes

| Condition | Windows attribute |
|---|---|
| `S_ISDIR` | `FILE_ATTRIBUTE_DIRECTORY` |
| regular file | `FILE_ATTRIBUTE_ARCHIVE` (or `NORMAL` if nothing else applies) |
| name starts with `.` and option `hide_dotfiles` (default on), except the root | `FILE_ATTRIBUTE_HIDDEN` |
| not writable by us (rule below) and option `map_readonly` (default on) | `FILE_ATTRIBUTE_READONLY` (files only; for directories NTFS's RO bit means "customized folder", so never set) |
| read-only mount | `FILE_ATTRIBUTE_READONLY` on files |
| symlink in `follow` mode | attributes of the target. A dangling link is a 0-byte file with `HIDDEN\|SYSTEM`. |
| FIFO, socket, device | hidden from listings unless `show_special`. Shown as 0-byte `SYSTEM` files; opening for data → `STATUS_ACCESS_DENIED`. |

**"Writable by us" rule.** We know our remote uid and primary gid once discovered (section 3.4), and the
supplementary group list only with `identity_probe = exec`.
- If our uid is unknown (not yet learned): writable if any `w` bit is set.
- If uid == ours: use `S_IWUSR`.
- Else, if gid is our primary gid or in our known supplementary groups: use `S_IWGRP`.
- Else, if supplementary groups are unknown (the default): writable if `S_IWGRP|S_IWOTH`.
- Else: use `S_IWOTH`.
- Uid 0 is treated as owner of everything when we are root.

The rule errs toward "writable": a false read-only blocks legitimate saves in many apps, while a false
writable just yields "access denied" from the server.

**Execute hint.** `S_IXUSR` (as owner) or `S_IXOTH` maps to the `FILE_EXECUTE` right in the synthesized
DACL (Dokany only, 3.3). There is no attribute for it. Mode is preserved across in-place overwrites
(SFTP `TRUNC` keeps it).

**Windows → POSIX** (`SetFileAttributes`, PROPPATCH `Win32FileAttributes`):
- Setting `READONLY` → `chmod` clearing all `w` bits.
- Clearing `READONLY` → set `S_IWUSR` (plus `S_IWGRP` if `umask` allows).
- `HIDDEN`, `SYSTEM`, `ARCHIVE`, `NOT_CONTENT_INDEXED`, `OFFLINE`, `TEMPORARY`: accepted and ignored
  (success). Office and installers set these routinely, and failing breaks them.

### 3.2 Times

- FILETIME = (unix_seconds + 11644473600) × 10^7. SFTP v3 times are 32-bit unsigned seconds:
  1-second granularity, no dates before 1970 or after 2106. Out-of-range values set from Windows are
  clamped and logged.
- **Creation time**: SFTP v3 has none. Reported = mtime. Setting it is accepted and ignored. (If
  `sd_sftp` exposes a birth time from a future extension, we use it.)
- **Last access**: reported from atime. Setting atime or mtime needs both in one `SETSTAT`
  (`ACMODTIME`), so the vfs fills in the other from the cache.
- **Change time** (`ChangeTime` in some info classes) = mtime.
- **Deferred time setting**: `SetFileTime(LastWriteTime)` on a handle with dirty data is stored and applied
  by `fsetstat` **after** the final flush at cleanup. Otherwise trailing writes would overwrite the mtime
  that copy tools (robocopy, Explorer) just set. A `-1` / `0xFFFFFFFF` FILETIME ("don't update") disables
  implicit mtime bumps for that handle.

### 3.3 Security descriptors

**Dokany** (`GetFileSecurity`), synthesized on demand and cached per (mode, uid, gid):

| SD part | Content |
|---|---|
| Owner | the mount owner's SID if `uid == our uid`; else `S-1-22-1-<uid>` (Unix user SID authority, as used by Samba and the Windows NFS client) |
| Group | `S-1-22-2-<gid>` |
| DACL | protected (no inheritance). ACE 1: Owner, rights from `u` bits. ACE 2: Group, from `g` bits. ACE 3: Everyone (`S-1-1-0`), from `o` bits. Plus `SYSTEM` full control if the profile option `allow_system` is on (default on). |

Bit → rights: `r` → `FILE_GENERIC_READ` (dirs: + `FILE_LIST_DIRECTORY|FILE_TRAVERSE`); `w` →
`FILE_GENERIC_WRITE|DELETE` (dirs: + `FILE_ADD_FILE|FILE_ADD_SUBDIRECTORY|FILE_DELETE_CHILD`); `x` →
`FILE_GENERIC_EXECUTE`. Owner always gets `READ_CONTROL|WRITE_DAC|WRITE_OWNER|FILE_READ_ATTRIBUTES|
FILE_WRITE_ATTRIBUTES`, so Explorer's Security tab works. The SD is advisory: Dokany does no access check
against it. The server enforces real permissions, and the vfs enforces the read-only mount and user
isolation (6.7).

`SetFileSecurity`:
- If the new DACL consists only of allow ACEs for owner/group/Everyone (or their S-1-22 / mount-owner
  equivalents), compute the mode and `chmod`.
- Otherwise return success without change (option `strict_acl` → `STATUS_ACCESS_DENIED`). Robocopy
  `/COPYALL` and installers then work.
- Owner and group changes are ignored. `chown` is generally root-only and the SID cannot be mapped back.

**WebDAV**: the redirector has no security descriptor support. Explorer shows no Security tab, so nothing
is synthesized. Read-only is conveyed with `Win32FileAttributes`.

### 3.4 Remote identity discovery (D10, C18, R13)

SFTP v3 has no "who am I" request, and an exec channel (`id -u; id -G`) fails on `ForceCommand
internal-sftp` servers, runs login scripts and writes audit-log noise. Default: **no exec**.

1. **At connect** (primary connection, every generation): `sd_sftp` stats the home directory after
   `realpath(".")` and reports its owner in `server_info.identity` (`SD_SFTP_ID_HOME_OWNER`, 01 §10.3,
   §11). Its owner uid is taken as our *provisional* uid, its gid as our provisional primary gid.
   Provisional because the home may be owned by another account (shared or chrooted homes, root-owned
   chroot directories, `/` as home).
2. **Confirmation**: the attributes returned (`OPEN` + `FSTAT`, or `MKDIR` + `LSTAT`) for the first
   file or directory this mount creates give the **definitive** uid and primary gid (a newly created
   object is owned by the creating uid; the gid may come from a setgid parent, so the gid is taken as
   definitive only if the parent has no `S_ISGID`). The result is cached per server identity (host key
   fingerprint + username) in the host for the session, so later mounts start definitive.
3. If the home is owned by uid 0 while the profile's username is not `root`, the provisional uid is not
   used; the uid stays unknown until step 2, and the rule in 3.1 falls back to "any `w` bit".
4. **Supplementary groups** are unknown by default; 3.1's "g or o writable" rule applies.
5. **`identity_probe = exec`** (profile option, default `owner`): `sd_mount` sets
   `SD_SFTP_OPT_IDENTITY_EXEC`, and `sd_sftp` itself runs the fixed command `id -u; id -G` once per
   generation on an exec channel of the primary connection (5 s timeout, 01 §11 step 5); the result
   arrives in `server_info.identity` with `SD_SFTP_ID_EXEC` and supplementary gids. `sd_vfs` reads it on
   every `READY_INFO`; there is no separate vfs call. Any failure (exec refused, non-numeric output,
   timeout) leaves the identity at `SD_SFTP_ID_HOME_OWNER`, so steps 1–4 apply; 01 logs it once.
6. `users-groups-by-id@openssh.com` (when advertised) is used for names only (UI and the Security tab's
   display), never for identity.

A change of the learned uid between generations (rare: different account after a server-side change)
drops the cached security descriptors and `win_attrs` of all nodes.

---

## 4. Caching, read-ahead, write modes

### 4.1 Metadata cache

| Item | Default TTL | Option |
|---|---|---|
| attributes (positive) | 30 s | `attr_ttl` |
| directory listing | 30 s | `dir_ttl` |
| negative entry | 10 s | `neg_ttl` |
| revalidate on open-for-data | if attr age > 1 s | `open_revalidate` (0 = always, -1 = never) |
| statvfs | 30 s | none |

- **Local mutations update the cache in place; nothing is merely invalidated.** Create inserts the child
  into the parent listing. Write updates size = max(size, end) and marks mtime "pending" (refreshed by
  `fstat` after flush). Rename moves the entry. Delete marks it negative. Setattr updates fields from the
  request, then from the server's reply when `fstat` is cheap (it is pipelined right after `fsetstat`).
- **Single-flight**: concurrent misses for the same node or directory wait on one in-flight request.
- **Change detection.** When a refreshed listing or attr differs from the cache, the vfs raises a change
  event. `sd_dokan` forwards it via `DokanNotifyCreate/Delete/Update/Rename`, so Explorer windows refresh.
  WebDAV has no push channel.
- Explicit refresh: `shelldrive refresh <drive>[\path]` and a tray action. These drop TTLs for a subtree.
- **Explorer probe suppression**: names that Explorer and shell extensions probe constantly
  (`desktop.ini`, `Thumbs.db`, `folder.jpg`, `folder.gif`, `AutoRun.inf`, `$RECYCLE.BIN`,
  `System Volume Information`) get a 300 s negative TTL when absent.

### 4.2 Data cache

Block-based. Block size 256 KiB, aligned. Two tiers.

**Memory tier**
- Global per process, shared by all mounts (C46: there is no per-profile memory budget).
- Budget from `settings.ini [cache] memory` (03 schema), passed by the host at process start: default
  min(256 MB, RAM/16), min 16 MB.
- LRU in 16 shards (lock per shard). Key: (mount id, file_id, validator generation, block index).

**Disk tier** (optional, per profile `read_cache_disk`, default 0 = off; UI suggests 2048 MB)
- Location: chosen by the host and passed as `sd_vfs_options.disk_cache_dir` (C12; 03 §3.2 owns the
  paths): per-user `<LocalAppData>\ShellDrive\cache\<profile-id>\`, service/global mounts
  `%ProgramData%\ShellDrive\service\cache\<profile-id>\` with an explicit SYSTEM+Administrators-only DACL.
  `sd_vfs` creates nothing outside the directory it is given.
- One sparse data file per remote file (`FSCTL_SET_SPARSE`; on FAT just a regular file). Named by the hex
  SHA-256 of (host key fingerprint, remote absolute path).
- A small header file holds the validator (size, mtime), a block bitmap and the last-use time.
- Eviction: LRU by last use when the total exceeds the limit; a background trim runs every 60 s and at
  startup.
- Writes to cache files are best effort; I/O errors disable the disk tier for the session.
- Cache files are written with `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`.
- The disk cache holds plaintext copies of remote files in the user's profile. The UI states this, and
  "Clear cache" deletes it. There is no DPAPI encryption (cost/benefit; the profile ACL already restricts
  it to the user).

**Coherency.**
- Cached data is valid only while the node's current validator (size, mtime) equals the validator recorded
  when the data was fetched. Any attr refresh that changes it drops all blocks of that node, in both tiers
  (the disk file is truncated, not deleted).
- 1-second mtime granularity plus an unchanged size can hide a rewrite. Mitigation: if mtime is within 2 s
  of the server time observed at fetch (estimated from our own last write or from `statvfs` round trips),
  the blocks are tagged "hot". Hot blocks are not trusted past `attr_ttl` and are not persisted to disk.
- Local writes update cached blocks in place once submitted (both write modes), and the validator is
  updated after the acknowledgement (write-through) or after flush and `fstat` (write-behind). A write
  that fails drops the affected blocks.
- `FILE_FLAG_NO_BUFFERING` and Dokany `Nocache` / `PagingIo` reads still use the cache. Coherency is
  ours to maintain; the kernel cache above Dokany is separate.

### 4.3 Read-ahead

- Sequential detection per handle: offset == `ra_next`.
- The window starts at 256 KiB and doubles per sequential hit up to `max_readahead` (default 8 MiB;
  covers a bandwidth-delay product of 100 Mbit/s × 640 ms).
- Window and outstanding requests can also be sized from the estimates `sd_sftp_session_stats()` exports
  (R16: `srtt_ms`, `rttvar_ms`, `rx_bps`, `tx_bps`): `window = clamp(2 × rx_bps × srtt)`. With a pool,
  the window is per mount; on a handle opened with `SD_SFTP_O_STRIPED`, `sd_sftp` spreads it over the
  connections (5.6).
- A random access resets the window. `FILE_FLAG_SEQUENTIAL_SCAN` starts at 2 MiB. `RANDOM_ACCESS`
  disables read-ahead.
- `sd_vfs` owns chunking (C15): it issues SFTP reads of `min(server max read, 256 KiB)` (default 32 KiB
  without `limits@openssh.com`), so each submission is exactly one wire request (01 still splits larger
  requests, which the vfs never relies on). Reads are pipelined with up to `max_inflight_reads` (default
  64) per connection. Results land in cache blocks.
- Short reads not at EOF are re-issued for the remainder (01 does this inside a request; the vfs handles
  a short contiguous prefix the same way). Some servers cap read size silently.
- `SD_E_BUSY` (01's bounded pending queue, R5) is treated as backpressure: the read-ahead pauses until a
  completion on that connection, and a demand read waits instead of failing.
- The caller's read completes as soon as its own range is present; read-ahead continues in the
  background.

### 4.4 Write modes, flush and close (D9)

Profile option `write_mode = through | behind`, **default `through`** (amendment A5 as rewritten by D9:
"By default every write is acknowledged by the server before it completes for the application. Profiles
may opt into write-behind, in which case …"). Policy may lock the key (03 schema).

**Common to both modes**
- `sd_vfs` splits each write into SFTP writes of up to the server's max write length (default 32 KiB
  without `limits@openssh.com`; C15) and submits them all at once, pipelined (and striped across pool
  connections for large writes, 5.6). Writes to one node never have two overlapping extents in flight at
  the same time; a write that overlaps an in-flight extent waits for its ack, because 01 guarantees
  ordering only per handle, not across handles or connections.
- Cached blocks are updated on submission (4.2).
- `SD_E_BUSY` from 01 is backpressure, never an error to the application.
- **`FlushFileBuffers`** (Dokany) / **end of PUT** (WebDAV): wait for every outstanding write of the node
  on every connection, then `fsync@openssh.com` (once, on any of the node's handles: POSIX `fsync`
  flushes the file, not one descriptor) if advertised and `fsync_on_flush` (default on). Returns the
  first error, if any.
- **Cleanup** (last handle to the file object): drain synchronously (Dokany timeout reset per 1 MiB of
  progress, 6.6), apply deferred times (3.2), close remote handles when no other local handle uses them.
- `SetEndOfFile` / `SetAllocationSize` shrinking: drop queued extents beyond the new size, drain the rest,
  then `fsetstat(size)`. Growing: `fsetstat(size)` only; the gap reads as zeros.
- WebDAV: the redirector itself buffers the whole file and sends one PUT at close (7.6), and the PUT
  response is sent only after the drain and fsync above, with the first error as its status. The PUT
  response is therefore the acknowledgement point on WebDAV in **both** modes, and the body always
  streams through a bounded 16 MiB window; `write_mode` changes nothing observable there. The
  redirector's own delayed upload at close is outside our control and is documented.

**`write_mode = through` (default)**
- `sd_vfs_write` returns only when every SFTP write of the call has been acknowledged. The status of the
  call is the application's `WriteFile` result: the first failed ack (mapped through the `sd_err` table)
  is returned **on that call**. No error is sticky; the next write is tried normally, as on a local disk.
- A write that completes with `SD_E_DISCONNECTED` or `SD_E_TIMEOUT` fails the call
  (`STATUS_CONNECTION_DISCONNECTED` / `STATUS_IO_TIMEOUT`). Because the request may have been executed
  (`maybe_executed`, 01 §10.6), the node records "size may include [off, off+len)" for the identity check
  after reconnect (5.3). The vfs never retransmits on its own in this mode, **except** within a pool:
  when a chunk fails with `SD_E_DISCONNECTED` and `session_ready = 1` (only a *secondary* connection was
  lost; the session and its handles are still valid, 01 §10.9), the vfs resubmits that chunk at once on the
  same `sd_sftp_file`, and `sd_sftp` routes it to a live connection (same bytes, same offsets: idempotent
  pwrite; 5.6). The application sees success only if every byte was acknowledged.
- No coalescing delay: the write is sent at once.
- Close semantics: every write of the handle has already completed, so cleanup only waits for writes
  that other threads still have in flight on the same node, then applies deferred times. A close cannot
  lose acknowledged data, and an unacknowledged write was already reported as failed to the application.
  `write_failed` is not raised in this mode (there is nothing the application was not told).
- Throughput depends on the application's write size and the RTT (one round trip per `WriteFile` call
  at minimum). Explorer and `copy` use large writes; see section 11 for the targets in this mode.
- Verify (Dokany): whether Dokany 2.3.1's kernel driver routes cached (non-`NO_BUFFERING`) application
  writes through the Cache Manager and delivers them later as `PagingIo` writes. If it does, the
  "acknowledged before completing" guarantee holds for every write that reaches `sd_vfs`, and for the
  application at `FlushFileBuffers` and `CloseHandle` (cleanup flushes the kernel cache before our
  `Cleanup`), but not per `WriteFile`; a lazy-writer failure then surfaces as Windows' standard
  "Delayed Write Failed" for network volumes. The result goes into the documentation of A5.

**`write_mode = behind` (opt-in)**
- Writes copy into the node's dirty-extent list (coalesced) and into cached blocks. The call returns once
  the data is queued.
- Sequential writes are sent immediately. The window bounds the unacknowledged data: `wb_window` default
  16 MiB per node, `wb_window_mount` 64 MiB per mount. When it is full, the writer blocks until acks
  arrive (backpressure; Dokany timeout extended with `DokanResetTimeout`).
- Non-sequential small writes are held up to 500 ms or 1 MiB to coalesce, then sent.
- **Errors are sticky.** The first failed write ack sets `node.wq.error`. Every subsequent write, flush
  and cleanup on that node returns it until the last handle closes.
- **Cleanup** drains as above; a failure there cannot be returned (`Cleanup` is `void`), so the vfs
  raises `SD_VFS_EV_WRITE_FAILED` (path, bytes lost, reason). The host turns it into the `write_failed`
  notification, which is always on, cannot be disabled and is mirrored in the event list (C45).
- **Disconnect**: extents sent but not acknowledged are kept up to `reconnect_grace` (default 60 s) and
  retransmitted after reconnect if the identity check passes (5.3). New writes during the outage fail
  (FS-7). Expiry or a failed identity check → sticky `SD_VFS_E_DISCONNECTED` / `SD_VFS_E_STALE` plus
  `SD_VFS_EV_WRITE_FAILED`.
- A handle opened with `FILE_FLAG_WRITE_THROUGH` (Dokany `WRITE_THROUGH` create option) behaves as
  `write_mode = through` for its own writes.
- Unmount and logoff/shutdown (`sd_vfs_quiesce`, 6.6) drain within their budget; data still dirty at the
  end of the budget is reported through `SD_VFS_EV_WRITE_FAILED`.

| Event | `through` (default) | `behind` (opt-in) |
|---|---|---|
| `WriteFile` returns | after all acks | after queueing (blocks only on a full window) |
| server error on a write | returned by that `WriteFile` | sticky; returned by a later write, flush or cleanup |
| disconnect mid-write | that `WriteFile` fails | grace retransmit ≤ 60 s, else `write_failed` |
| `FlushFileBuffers` | waits for in-flight writes + fsync | drains window + fsync, returns sticky error |
| last close (`Cleanup`) | nothing to drain (other handles only) | synchronous drain; failure → `write_failed` |
| data at risk if the app ignores `FlushFileBuffers` | none beyond a kernel cache (verify above) | up to 16 MiB per node / 64 MiB per mount |

---

## 5. Connection loss, reconnect, threading

### 5.1 States

The vfs follows 01's per-connection states (`SD_SFTP_ST_*`, 01 §10.4). For the mount as a whole only the
**primary** connection counts (5.6):

| Primary connection state | vfs mount state |
|---|---|
| `SD_SFTP_ST_READY` (generation g) | connected (g) |
| `SD_SFTP_ST_DISCONNECTED`, `RECONNECT_WAIT`, `CONNECTING` | disconnected (reconnecting with backoff) |
| `SD_SFTP_ST_AUTH_REQUIRED` | disconnected, waiting for a user prompt (`sd_mount` routes it) |
| `SD_SFTP_ST_FAILED` | failed: the drive stays mapped in the offline state (cached reads work, everything else `SD_VFS_E_DISCONNECTED`); the tray offers Reconnect; only the user or a policy unmounts (00 §4) |
| `SD_SFTP_ST_CLOSED` | unmounting |

`sd_sftp` completes every outstanding request with `SD_E_DISCONNECTED` on disconnect, marks every
`sd_sftp_file` stale, and increments the generation on reconnect (R8, R9). The vfs re-reads
`server_info` (limits, extensions, home) on every `SD_SFTP_EV_READY_INFO`, because they may change.
Secondary pool connections are internal to the session: their loss produces only `SD_SFTP_EV_POOL`
events and shrinks the pool (5.6); the session state is the primary's.

### 5.2 Behavior while disconnected

| Operation | Behavior |
|---|---|
| stat / lookup / listing | Served from cache ignoring TTL (positive and negative). Unknown → submitted with `SD_SFTP_REQ_WAIT_READY` and `timeout_ms = offline_wait` (default 3 s), then `SD_VFS_E_DISCONNECTED`. Not `NOT_FOUND`: apps must not conclude a file was deleted. |
| read | Served from cache if blocks are present and the validator was valid at disconnect. Otherwise `WAIT_READY` up to `offline_wait`, then `SD_VFS_E_DISCONNECTED`. |
| write / create / delete / rename / setattr / mkdir | Fail immediately with `SD_VFS_E_DISCONNECTED`; writes are never submitted with `WAIT_READY` (01 §10.5). Mutations other than writes wait at most `offline_wait` if a reconnect attempt is already in progress. No offline queue. |
| `GetDiskFreeSpace` | last known values |
| Open with write access | fails `SD_VFS_E_DISCONNECTED` at create time |

Error mapping for `SD_VFS_E_DISCONNECTED`:
- Dokany: `STATUS_CONNECTION_DISCONNECTED` (Win32 `ERROR_NETNAME_DELETED`, "The specified network name
  is no longer available"). Users and apps know this from SMB.
- WebDAV: HTTP `503 Service Unavailable` with `Retry-After: 5`.

The tray shows "Offline (reconnecting)". Dokany volume label suffix while offline: a localized string the
host passes in `sd_vfs_options.offline_label_suffix` (C45; the service uses the machine default language),
returned via `GetVolumeInformation`. `sd_vfs` itself produces no user-visible text.

### 5.3 Re-opening handles after reconnect

- Remote handles carry the session generation (01 marks them stale when the primary connection is
  lost; the loss of a secondary does not make them stale, 01 §10.9). On first use after the reconnect, a
  node with live local handles reopens lazily with `sd_sftp_file_reopen` (01 §10.6: `OPEN` with the same
  flags minus `CREAT`/`TRUNC`/`EXCL`, plus `FSTAT`); `sd_sftp` reopens striped sub-handles itself.
- **Identity check**: the fresh attributes must match the validator recorded before the disconnect (size
  adjusted for our acknowledged writes, mtime). A write that failed with `maybe_executed` (5.6, 4.4) widens
  the accepted size to "either without or with that extent", and its mtime is not compared. On mismatch,
  or if the file is gone:
  - nodes with nothing unacknowledged drop their cache and continue (read handles see the new content;
    Windows makes no stronger promise for network files);
  - in write-behind mode, nodes with unacknowledged dirty data are **conflicted**. Writes are discarded,
    the handle is marked `FAILED`, all further I/O returns `SD_VFS_E_STALE` → `STATUS_FILE_INVALID`
    (Win32 `ERROR_FILE_INVALID`: the file was externally altered and the open handle is no longer valid),
    and `SD_VFS_EV_WRITE_FAILED` is raised.
- **In-flight writes, write-behind only**: extents sent but not acknowledged at disconnect stay in memory
  up to `reconnect_grace` (default 60 s). Within the grace window and after a passing identity check they
  are re-sent (pwrite semantics are idempotent). This is retransmission, not an offline queue: new writes
  during the outage still fail (5.2). When grace expires the node goes `FAILED` with the sticky error
  `SD_VFS_E_DISCONNECTED`. In write-through mode there is nothing to retransmit: the application already
  got the error.
- Mutating path operations that completed with `maybe_executed` (rename, remove, mkdir, setstat) are
  never retried blindly: after reconnect the affected nodes are re-`lstat`ed and the cache is corrected
  (01 §10.6).
- Directory enumeration snapshots survive reconnects (they are local).
- WebDAV requests are short-lived; an interrupted GET or PUT just fails (the client sees a TCP reset or
  503).

### 5.4 Threading model

This is the filesystem part of the host threading model (00 §4); the cross-module rules of 00 §4.1 are
normative and restated where they bind `sd_vfs`.

- **Dokany**: Dokany calls callbacks on its own worker threads (multi-threaded; `SingleThread = FALSE`).
  `sd_vfs` exposes a **synchronous** API. Internally each operation submits async requests to `sd_sftp`
  and waits on a per-thread auto-reset event (TLS-pooled `sd_waiter`; no Vista-only primitives).
- **WebDAV**: one accept thread (`AcceptEx` on IOCP, XP-compatible) and a worker pool (default 8, max 32)
  that calls the same synchronous vfs API. Streaming GET uses the vfs read-ahead; the worker just pulls
  blocks. **At least 2 workers are reserved** for `OPTIONS`, `PROPFIND`, `LOCK`/`UNLOCK` and
  `PROPPATCH`, so streaming GET/PUT workers waiting on backpressure can never delay those past the
  redirector's 60 s `SendReceiveTimeoutInSec` (rule 5).
- **`sd_sftp` completions** run on each connection's I/O thread (one per SSH chain, 01 D2). A completion
  callback **never takes `node.lock` or a cache shard lock** (rule 1). It either fills the waiter's result
  block and calls `SetEvent`, or, for completions without a waiter (read-ahead blocks, write-behind
  acknowledgements, background revalidation), pushes the completion to the vfs background queue. All node
  and cache mutation happens on vfs threads (Dokany/WebDAV workers or the background thread). A callback
  MUST NOT block or call any `*_sync` wrapper.
- **Background thread per process** (timer queue via `CreateTimerQueueTimer`, XP+, plus the completion
  queue above): write-behind coalescing deadlines, completion processing, disk cache trim, reconnect
  grace expiry, Dokany change notifications.
- **Host control thread** (`sd_mount`, 03): the only place (besides CLI threads) that may call `*_sync`
  wrappers, `sd_vfs_quiesce`/`sd_vfs_unmount`, `sd_sftp_session_close`/`_destroy` and `DokanCloseHandle`
  (rule 3, C33). Dokany callbacks, WebDAV workers and I/O threads never call them.
- Prompts (auth on reconnect of any pool connection) never reach `sd_vfs`; `sd_mount` routes them to the
  IPC thread (rule 4). `known_hosts` and credential lookups run on worker items (rule 7).

### 5.5 Locks and ordering

The build targets XP (v141_xp), so `SRWLOCK` and `CONDITION_VARIABLE` (Vista+) are not used.
`sd_rwlock` is a small writer-preferring RW lock built on a `CRITICAL_SECTION` plus two events, with an
`Interlocked*` fast path. If profiling shows contention, the Vista+ SRW lock may be picked at runtime
through `GetProcAddress`.

Lock order (acquire left to right only):

```
mount.tree_lock (rw)  <  node.lock (parent before child; two unrelated nodes by address)
   <  share_registry.lock  <  cache shard lock
```

- The order ends at the cache shard lock. **No vfs lock is held across any `sd_sftp_*` submission**
  (rule 2), so there is no lock-order dependency on 01's internal queue locks: an operation collects what
  to send under its locks, releases them, then submits.
- No vfs lock is held while waiting for a network reply.
- An operation drops its locks, waits, and re-validates node state (generation counters) after waking.
- `tree_lock` is exclusive only for structural changes (insert/evict/move nodes); lookups take it shared.
- Per-node state (attrs, share, wq, remote handle slots) is under `node.lock`.

### 5.6 Connection pool per mount (D18, D19)

**What `sd_vfs` receives.** One `sd_sftp_session *` per mount, whatever the pool size (01 §10.9).
`sd_mount` sets `sd_sftp_options.connections` from the profile (`connections = 1..4`, default 1);
`sd_sftp` opens, admits, routes and reconnects the members itself. The vfs sees the pool only through
`SD_SFTP_O_STRIPED`, `SD_SFTP_EV_POOL` events, per-member statistics (`sd_sftp_session_stats()`), the
`session_ready` flag in completions, and concurrent completions (01 §10.8 item 2). Pool rules owned by
01, restated because the vfs depends on them:
- Members beyond the primary are opened **only when authentication is non-interactive** (key, agent,
  stored password or passphrase), so the user never gets repeated 2FA prompts; otherwise the pool stays
  at 1. A secondary member that would need a prompt is dropped, never prompted (the host reports
  `warning pool_limited`, 03 §3.4).
- The primary carries two SFTP channels (meta + bulk, C17; auto-degrade to one, in which case 01 serves
  the meta class first). **Extra members open one bulk channel only** (D19).
- Secondary members are opened after the primary is `READY` and must present the **same host key
  fingerprint and the same `realpath(".")`** as the primary (01 §10.9). A mismatch (DNS round robin or a
  load balancer in front of different servers) drops that member. Shared caches and the share registry
  are keyed by the primary's identity.
- A server refusing extra connections or sessions (`MaxStartups`, `MaxSessions`, per-user limits) shrinks
  the pool; the vfs never depends on more than the primary.

**Request routing** (done by `sd_sftp`; listed so the vfs knows what to expect).

| Request class | Where |
|---|---|
| Path operations: lookup `lstat`/`stat`, `opendir`/`readdir`, `realpath`, `mkdir`, `rmdir`, `remove`, `rename`, `setstat`, `statvfs`, `readlink`; attribute-only opens (`SD_SFTP_REQ_CLASS_META`) | **primary**, meta channel |
| Create/open that may create or truncate (2.1 exceptions), first data handle of a node (lazy open, 2.1) | primary, bulk channel (01's handle binding) |
| Reads and writes on a handle opened with `SD_SFTP_O_STRIPED` | striped over the members by `sd_sftp` (below) |
| Reads and writes on other handles | the handle's channel on the primary |
| `fstat`, `fsetstat`, `fsync`, `close` on a striped handle | barriers inside `sd_sftp` (wait for all parts, then the primary sub-handle) |
| Identity (3.4), case detection (1.3) | primary |

**Striping policy (vfs side).** The vfs sets `SD_SFTP_O_STRIPED` on a data handle only when
`connections > 1`, the file is at least `stripe_min_file` (8 MiB) or the handle is opened for a large
sequential write (first write call ≥ 1 MiB), and the access pattern is sequential (`SEQUENTIAL_SCAN`,
Explorer/`copy` patterns, or the read-ahead state of 4.3). Small files, random I/O, `APPEND` handles and
directories never stripe. Everything else is 01's: sub-handles opened lazily on the members with
`oflags & ~(CREAT|TRUNC|EXCL)`, `stripe_bytes` units (1 MiB) assigned `k mod live_members`, requests
split at unit boundaries, ordering per byte range, `max-open-handles` per member (01 §10.9).
- The read-ahead window (4.3) is issued in chunk-sized reads as usual; results land in cache blocks, so
  arrival order does not matter.
- Write chunks never overlap in flight (4.4). A size-extending chunk sent on member B before a lower
  chunk on member A lands creates a temporary hole on the server; the final size and content are correct
  once all chunks are acknowledged, and the flush/fsync rule in 4.4 waits for them (the `fsync` barrier).

**Reconnect.** Each member reconnects on its own backoff inside `sd_sftp` (01 §10.9).
- Loss of a **secondary**: the session stays `READY` and every handle stays valid. `sd_sftp` reissues the
  lost member's in-flight reads on the primary itself. Its in-flight writes complete with
  `SD_E_DISCONNECTED`, `maybe_executed = 1` and `session_ready = 1`; the vfs resubmits them at once on the
  same handle (4.4), which is not an offline queue because the mount is connected.
- Loss of the **primary**: the session-level disconnect (5.1). `sd_sftp` closes every secondary with it,
  all handles go stale, and writes, new opens and path operations follow 5.2, so "writes fail while
  disconnected" does not depend on the pool size. After `READY`, nodes reopen lazily (5.3) and the
  members are re-admitted by 01.
- A member refused 3 times is abandoned by 01 for the generation; the pool runs smaller meanwhile.

**Accounting.** `sd_vfs_stats` copies the per-member part of `sd_sftp_session_stats()` (state, srtt,
bytes, in-flight) plus its own counters (`status --stats`, C7). Memory per mount (11) counts all members.

### 5.7 Deadlines and timeouts (C16)

- Every request `sd_vfs` submits carries `timeout_ms` (01 `sd_sftp_reqopt`): **25 s on Dokany mounts**
  (below the 30 s Dokany request timeout, 6.6) and **50 s on WebDAV mounts** (below the redirector's
  60 s `SendReceiveTimeoutInSec`). A vfs operation that needs several round trips (lookup + listing +
  open) gives each request the remaining part of one overall budget of the same size.
- On any request timeout, 01 sends an immediate `keepalive@openssh.com` on that connection and declares it
  dead if the probe is unanswered within `min(5 s, 3 × srtt)`. The vfs does not wait for that verdict:
  the timed-out operation returns `SD_VFS_E_TIMEOUT` (`STATUS_IO_TIMEOUT` / HTTP 504) at once, and
  operations started after the verdict see `SD_VFS_E_DISCONNECTED`. So a dead link surfaces as
  `TIMEOUT` or `DISCONNECTED` within the Dokany deadline (rule 6).
- Waits that make progress (write backpressure, cleanup drain, a huge listing, `offline_wait`) call
  `DokanResetTimeout(30000)` on progress only and restart their budget; a wait without progress never
  extends the deadline.
- A reply that arrives after its request timed out is discarded by 01 (cancel semantics), and the vfs
  state stays consistent because every waiter re-validates after waking (5.5).

---

## 6. `sd_dokan` — Dokany adapter

### 6.1 Version, OS and architecture facts

- Latest release: **v2.3.1.1000** (28 Sep 2025), the newest on the
  [GitHub releases page](https://github.com/dokan-dev/dokany/releases) as checked 2026-10-24.
  The header declares `DOKAN_VERSION 231`, `DOKAN_MINIMUM_COMPATIBLE_VERSION 200`
  ([dokan.h](https://raw.githubusercontent.com/dokan-dev/dokany/master/dokan/dokan.h)).
- OS: Windows 7 SP1 through 11, Server 2008 R2 SP1 through 2022; platforms x86, x64, ARM, ARM64
  ([README](https://github.com/dokan-dev/dokany)).
  - The **ARM64 MSI** exists since 2.2.0 ([CHANGELOG](https://raw.githubusercontent.com/dokan-dev/dokany/master/CHANGELOG.md)).
  - No ARM32 installer is published, and Windows RT cannot load third-party drivers, so **ARM32 is
    WebDAV-only**, best effort (D5, amendment A7).
- **Signing.** Release drivers are signed for all platforms (README). 2.1.0 replaced the expired EV
  certificate and adapted installation because "Microsoft has changed the rules of which type of drivers
  (primitive) can be signed"; the INF became a primitive driver INF and `dokanctl` installs the service
  ([v2.1.0.1000](https://github.com/dokan-dev/dokany/releases/tag/v2.1.0.1000), CHANGELOG).
  For Windows 10/11 this implies Microsoft attestation signing through the Partner Center
  (verify: inspect the `dokan2.sys` signature chain).
  - **Windows 7**: a 2.1.0 user reports testing on Windows 7 and 10
    ([issue #1211](https://github.com/dokan-dev/dokany/issues/1211)), so the 2.1+ driver loads there.
    Windows 7 only validates SHA-2-signed kernel code with **KB4474419** (SHA-2 code signing support)
    and **KB4490628** (servicing stack) installed
    ([KB4474419](https://support.microsoft.com/help/4474419); vendor practice of requiring KB4490628 +
    KB4474419 + KB4534310: [Elo](https://elosupport.elotouch.com/hc/en-us/articles/31650918014871-How-to-Implement-SHA-2-Support-for-Windows-7-Driver-Installation-Driver-and-FW-Docs)).
    Without them the driver fails with Code 52.
  - SHA-2 support detection on Win7 / 2008 R2 and the install decision table are **04's** (§7.2/§7.3,
    normative; C32): `WinVerifyTrust` on the catalog, then the `ci.dll` version. If support is missing,
    the installer explains and does not install Dokany; WebDAV stays available. At run time
    `sd_dokan_probe()` (`DokanDriverVersion() != 0`) is the final authority.
  - Verify: actual load of the 2.3.1 x86 and x64 driver on a fully patched Win7 SP1 VM and on one with
    only KB4474419 + KB4490628.
- **Packaging (D32, C31)**: redistributed unmodified as published upstream. Lab check in the first week
  of M4: `dumpbin /dependents dokan2.dll` (and `dokannp2.dll`, `dokanctl.exe`) for every architecture.
  - If `dokan2.dll` has **no** VC++ runtime dependency: the official per-arch `Dokan_<arch>.msi` files are
    chained by our EXE and used for GPO/Intune.
  - If it depends on `vcruntime140*.dll`: the offline EXEs embed the official `DokanSetup.exe` bundle
    (which carries the VC++ redistributable, [Installation wiki](https://github.com/dokan-dev/dokany/wiki/Installation));
    the MSIs remain for GPO/Intune with the VC++ redistributable documented as a prerequisite.
  - `sd_dokan_probe()` reports `SD_DOKAN_NOT_INSTALLED` with the loader error when `dokan2.dll` exists
    but fails to load (missing runtime), so the UI can name the cause. Installer mechanics are 04 §7.

### 6.2 Dynamic loading and version gate

```c
/* sd_dokan_load.h (sketch) */
typedef struct sd_dokan_api {
    HMODULE  dll;
    ULONG    lib_version, driver_version;          /* e.g. 231 */
    VOID     (WINAPI *Init)(VOID);
    VOID     (WINAPI *Shutdown)(VOID);
    int      (WINAPI *CreateFileSystem)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS, DOKAN_HANDLE *);
    DWORD    (WINAPI *WaitForFileSystemClosed)(DOKAN_HANDLE, DWORD);
    VOID     (WINAPI *CloseHandle)(DOKAN_HANDLE);
    BOOL     (WINAPI *RemoveMountPoint)(LPCWSTR);
    ULONG    (WINAPI *Version)(VOID);
    ULONG    (WINAPI *DriverVersion)(VOID);
    BOOL     (WINAPI *ResetTimeout)(ULONG, PDOKAN_FILE_INFO);
    HANDLE   (WINAPI *OpenRequestorToken)(PDOKAN_FILE_INFO);
    BOOL     (WINAPI *IsNameInExpression)(LPCWSTR, LPCWSTR, BOOL);
    BOOL     (WINAPI *NotifyCreate)(DOKAN_HANDLE, LPCWSTR, BOOL);
    BOOL     (WINAPI *NotifyDelete)(DOKAN_HANDLE, LPCWSTR, BOOL);
    BOOL     (WINAPI *NotifyUpdate)(DOKAN_HANDLE, LPCWSTR);
    BOOL     (WINAPI *NotifyRename)(DOKAN_HANDLE, LPCWSTR, LPCWSTR, BOOL, BOOL);
    PDOKAN_MOUNT_POINT_INFO (WINAPI *GetMountPointList)(BOOL, PULONG);
    VOID     (WINAPI *ReleaseMountPointList)(PDOKAN_MOUNT_POINT_INFO);
} sd_dokan_api;

typedef enum sd_dokan_avail {
    SD_DOKAN_OK, SD_DOKAN_OS_UNSUPPORTED, SD_DOKAN_NOT_INSTALLED,
    SD_DOKAN_TOO_OLD,          /* < 2.1.0 (incl. 2.0.x) */
    SD_DOKAN_DRIVER_MISSING,   /* DokanDriverVersion() == 0 */
    SD_DOKAN_WOW64             /* our process arch != OS arch */
} sd_dokan_avail;

sd_dokan_avail sd_dokan_probe(sd_dokan_api *api);  /* never loads anything outside System32 */
```

- Load with `LoadLibraryExW(L"<GetSystemDirectoryW()>\\dokan2.dll", NULL, 0)`, always a full path,
  never the search path (DLL planting). Optionally `WinVerifyTrust` the file (XP+ API) and log the signer.
- No import-library link, no delay-load stub. Only `GetProcAddress`. The `DOKAN_*` ABI we compile
  against is **our own minimal declaration** in `src/sd_dokan/dokan_abi.h`, written from the documented
  ABI, frozen at 2.3.1, with a notice; no upstream header file is copied, which keeps the tree MIT-only
  (C38, D1).
- **Version gate**: `DokanVersion() >= 210 && DokanDriverVersion() >= 210`. The 2.1.0 changelog says
  "`DOKAN_OPTION_*` values were reordered and reassigned", so 2.0.x is ABI-incompatible with our
  constants and is rejected. `DOKAN_OPTIONS.Version` = `min(231, DokanVersion())`.
- Our process must match the OS architecture. The universal x86 stub launches the native exe; an x86 exe
  under WOW64 does not use Dokany.
- `DokanInit()` once per process, `DokanShutdown()` at exit.

### 6.3 Coexistence with other Dokany installations

- Dokany 1.x (`dokan1.sys`, `dokan1.dll`) and 2.x (`dokan2.sys`, `dokan2.dll`) use different file,
  driver and service names, so they coexist side by side. We ignore 1.x.
- Only one 2.x driver can be installed system-wide. Since 2.3.0, the Dokany installer fails if the driver
  is already present (release notes). Policy:
  - an existing 2.x >= 2.1.0 is used as is. We never downgrade it or replace it with ours; we use the
    installed `dokan2.dll`, which always matches the installed driver;
  - an existing 2.0.x → Dokany backend unavailable (`SD_DOKAN_TOO_OLD`). The UI explains that upgrading
    Dokany may affect the other product that installed it. Whether and how an upgrade is offered follows
    04's decision table (the upstream 2.3 installer refuses while a third-party 2.x driver is present).
    Nothing is uninstalled automatically;
  - our uninstaller removes Dokany only if our installer installed it (an MSI ref-count / registry
    marker) and no other mounts are live.
- The driver API is backward compatible from `DOKAN_MINIMUM_COMPATIBLE_VERSION` (200), so other apps
  built against older 2.x keep working when the system has 2.3.1.

### 6.4 Mount options

| Profile setting | DOKAN_OPTIONS |
|---|---|
| per-user drive letter | `CURRENT_SESSION`; `NETWORK` + `UNCName = \shelldrive\<share>` if the Dokany network provider (`dokannp2.dll`) is registered under `NetworkProvider\Order`, else plain (fixed). `<share>` is the profile name reduced to UNC-legal characters (letters, digits, `-`, `_`, `.`; ≤ 80 chars), made unique among live mounts with `-2`, `-3`...; it is stable for a profile, which Network Shortcuts rely on (10.3) |
| global drive (service) | no `CURRENT_SESSION`; `MOUNT_MANAGER`; `NETWORK` as above |
| folder mount point (`C:\mnt\host`, empty NTFS dir) | `MOUNT_MANAGER`, no `NETWORK` (network drives cannot be folder mounts). Verify that a folder mount works with `CURRENT_SESSION` for per-user use; otherwise folder mounts are global-only. |
| read-only | `WRITE_PROTECT` (plus vfs enforcement) |
| case-sensitive view | `CASE_SENSITIVE` |
| always | `Timeout = 30000` ms; `AllocationUnitSize = 4096`; `SectorSize = 512`; `SingleThread = FALSE`; not `REMOVABLE` (header doc: it can cause the app to be denied access and the drive to unmount unexpectedly); not `ALT_STREAM`; not `FILELOCK_USER_MODE`; `ENABLE_UNMOUNT_NETWORK_DRIVE` so Explorer's "Disconnect" works (we observe `Unmounted`) |
| global mounts | `VolumeSecurityDescriptor` granting the profile's `service_access` SIDs (03 §3.4.1; default `BUILTIN\Users`, `S-1-5-32-545`) read/execute, `Administrators`/`SYSTEM` full) |

Why the network drive type is the default: Explorer deletes permanently on network drives instead of
creating `$RECYCLE.BIN` on the remote, the indexer leaves it alone by default, and users see "Disconnect"
like SMB. On a fixed-type mount the vfs refuses creation of `\$RECYCLE.BIN` and
`\System Volume Information` with `STATUS_ACCESS_DENIED`, so Explorer falls back to permanent delete
with a prompt. Dokany 2.2.0 isolates network drives between users browsing UNC paths
([2.2.0 notes](https://github.com/dokan-dev/dokany/releases)).

### 6.5 Callback mapping (`DOKAN_OPERATIONS`, 2.x)

| Callback | `sd_vfs` call | Notes |
|---|---|---|
| `ZwCreateFile` | `sd_vfs_create(path, access, share, disposition, options, attrs, &h)` | Requestor check first (6.7). Use the kernel dispositions/options directly (table 2.2). `DokanFileInfo->IsDirectory` set/read. Return `STATUS_OBJECT_NAME_COLLISION` for opened-existing with `OPEN_IF`/`OVERWRITE_IF`. Store `h` in `Context`. |
| `Cleanup` | `sd_vfs_cleanup(h, DeletePending)` | flush (4.4), deferred times, delete if pending (2.4) |
| `CloseFile` | `sd_vfs_close(h)` | free handle; release remote handle refs |
| `ReadFile` | `sd_vfs_read(h, off, buf, len, &got)` | `PagingIo`/`Nocache` ignored for caching (4.2); EOF → `STATUS_END_OF_FILE` only if off ≥ size, else short read |
| `WriteFile` | `sd_vfs_write(h, off or EOF if WriteToEndOfFile, buf, len, &done)` | `PagingIo` writes must not extend the file past the cached size (truncate the request; NT rule) |
| `FlushFileBuffers` | `sd_vfs_flush(h)` | drain + fsync |
| `GetFileInformation` | `sd_vfs_getattr(h)` | fills `BY_HANDLE_FILE_INFORMATION`: attrs (3.1), times (3.2), `nFileIndex` = `file_id`, `nNumberOfLinks` = 1, volume serial |
| `FindFiles` | `sd_vfs_readdir(h, cb)` | snapshot; `.` and `..` added for non-root dirs; mangled names (1.3) |
| `FindFilesWithPattern` | NULL | Dokany then calls `FindFiles` and filters with `DokanIsNameInExpression` in the library |
| `SetFileAttributes` | `sd_vfs_set_winattrs` | 3.1 |
| `SetFileTime` | `sd_vfs_set_times(h, c, a, w)` | deferred if dirty (3.2) |
| `DeleteFile` / `DeleteDirectory` | `sd_vfs_can_delete(h)` | validate only; delete happens in `Cleanup` (2.4) |
| `MoveFile` | `sd_vfs_rename(h, new, replace)` | 2.5; `DokanNotifyRename` not needed (the kernel knows) |
| `SetEndOfFile` | `sd_vfs_truncate(h, size)` | 4.4 |
| `SetAllocationSize` | if `alloc < size` → truncate, else no-op | |
| `LockFile` / `UnlockFile` | NULL | kernel handles locks |
| `GetDiskFreeSpace` | `sd_vfs_statfs` | `statvfs@openssh.com` on the root: avail = `f_bavail×f_frsize`, total = `f_blocks×f_frsize`, free = `f_bfree×f_frsize`. Without the extension: 1 PiB free of 2 PiB, so Explorer never blocks copies on a guess (shown as "unknown" in our UI). |
| `GetVolumeInformation` | static | Label = profile name (+ the host-supplied localized offline suffix, 5.2). FS name `NTFS` by default (D23; profile option `volume_fs_name`, e.g. `ShellDrive`; some apps refuse names other than NTFS, so the compatibility list in 13 decides which apps to document). Flags: `FILE_CASE_PRESERVED_NAMES \| FILE_UNICODE_ON_DISK \| FILE_PERSISTENT_ACLS \| FILE_SUPPORTS_REMOTE_STORAGE`, `+FILE_CASE_SENSITIVE_SEARCH` in sensitive mode, `+FILE_READ_ONLY_VOLUME` if RO. No streams, reparse, hard links, object IDs. MaxComponentLength 255. |
| `Mounted` / `Unmounted` | mount manager state | `Unmounted` (e.g. Explorer "Disconnect") **only posts a message** to the host control thread (C33) and returns at once. The control thread then runs `sd_vfs_quiesce` → `sd_sftp_session_close` (which closes every pool member) → destroy (6.6). Calling `DokanCloseHandle`, `sd_vfs_unmount` or `sd_sftp_session_destroy` inside the callback would deadlock: Dokany waits for its callbacks, and destroy waits for the I/O thread. |
| `GetFileSecurity` / `SetFileSecurity` | `sd_vfs_get_sd` / `sd_vfs_set_sd` | 3.3; return `STATUS_BUFFER_OVERFLOW` with `LengthNeeded` when too small |
| `FindStreams` | NULL / `STATUS_NOT_IMPLEMENTED` | only the unnamed stream exists |

### 6.6 Timeouts and unmount

- Dokany's default per-request timeout is 15 s (dokan.h; verify). We set `Timeout = 30000` and call
  `DokanResetTimeout(30000)` only from operations that keep making progress: write backpressure, cleanup
  drain, listing a huge directory, waiting for reconnect within `offline_wait`.
- Every vfs operation has a hard deadline of 25 s, below the Dokany timeout (5.7, C16). A reply that
  arrives after the deadline is discarded, and the state stays consistent.
- Unmount, always on the host control thread (C33, 5.4): `sd_vfs_quiesce` (block new opens → drain all
  nodes with outstanding writes within a 30 s budget; in write-through mode this is only the writes in
  flight, in write-behind mode the dirty windows → close remote handles; `sd_sftp` closes the pool sub-handles), then
  `DokanCloseHandle` (2.1+ API: triggers unmount and waits;
  [CHANGELOG 2.0.0/2.1.0](https://raw.githubusercontent.com/dokan-dev/dokany/master/CHANGELOG.md)), then
  `sd_sftp_session_close` (one session, all pool members) and destroy after `CLOSED`. When the unmount was initiated by
  Dokany (`Unmounted` callback), `DokanCloseHandle` is still called from the control thread to release
  the handle. Forced unmount skips the drain budget and reports lost data (`SD_VFS_EV_WRITE_FAILED`).
- Process crash: the Dokany driver unmounts when the process handle closes. At next start `sd_mount`
  (03, stale-mapping cleanup) calls `DokanGetMountPointList` and `DokanRemoveMountPoint` for stale
  ShellDrive mount points, identified by the `\shelldrive\` UNC prefix or our registry record.

### 6.7 User isolation (Dokany)

A device object is reachable from other sessions even when the drive letter is session-local. In
`ZwCreateFile`, call `DokanOpenRequestorToken`, read `TokenUser`, and allow if:
- the user is the mount owner (per-user mount), or a member of the profile's `service_access` list (global mount;
  `CheckTokenMembership` on a duplicated impersonation token); or
- the user is `LocalSystem` and `allow_system` is on (Defender, the indexer).

Otherwise return `STATUS_ACCESS_DENIED`. The result is cached per (token LUID, SID) for 60 s to avoid
per-open token queries.

### 6.8 Folder mounts

`MountPoint` = an empty existing directory on a local NTFS volume. The vfs checks that it is empty and
on NTFS (`GetVolumeInformationW` reports NTFS and `FILE_SUPPORTS_REPARSE_POINTS`). Dokany with
`MOUNT_MANAGER` creates the mount-point reparse point; we remove leftovers at startup (6.6).

### 6.9 Symlinks and reparse points (D12, amendment A3)

`DOKAN_OPERATIONS` has no `FsControl` / `DeviceIoControl` callback
([dokan.h](https://raw.githubusercontent.com/dokan-dev/dokany/master/dokan/dokan.h)). A maintainer
stated that Dokan "doesn't support FSCTLs at all" ([dokan group](https://groups.google.com/g/dokan/c/Gj1KxRNOvAg)).
`ZwCreateFile` cannot return `STATUS_REPARSE` with a reparse buffer either. So
`FSCTL_GET_REPARSE_POINT`, `FSCTL_SET_REPARSE_POINT` and `IO_REPARSE_TAG_SYMLINK` resolution cannot be
implemented with unmodified Dokany 2.3.1.

**Decision (D12): reparse points are postponed** and revisited after 1.0. There is no fork and no
upstream work for now. A self-built Dokany fork was rejected: it would need our own EV certificate and
attestation signing (which only loads on Windows 10+) and would conflict with an existing official Dokany
installation. The requirement reads (A3): "Symlinks: follow them or hide them (both backends). Exposing
them as reparse points is deferred until Dokany ships an FSCTL callback in an official signed release."

Profile key `symlinks = follow | hide` (C29). The value `reparse` is reserved: profile validation
rejects it at save and at load with a clear, localized error (03), and `sd_vfs_options.symlinks` has no
value for it.

Supported symlink policies (both backends):
- `follow` (default). Listings use `lstat` attributes from READDIR. Entries with `S_IFLNK` get a
  pipelined `stat` to learn the target's type and size (single batch per listing; cached). Dangling or
  looping links → 0-byte `HIDDEN|SYSTEM` file; opening it for data → `STATUS_OBJECT_NAME_NOT_FOUND`;
  delete and rename act on the link itself (`REMOVE` / `RENAME` do not follow).
- `hide`: `S_IFLNK` entries are omitted from listings and lookups fail `NOT_FOUND`.

Creating symlinks from Windows (`mklink`) is not supported (it needs FSCTL; the Dokany kernel driver
fails the FSCTL itself. Verify the status `mklink` reports, for the documentation).

### 6.10 Recycle bin, AV and indexer

- Default network type avoids the Recycle Bin (6.4).
- `allow_system` lets Defender scan files on open. This costs a full read per first open of executables
  and archives; documented, with a profile toggle.

---

## 7. `sd_webdav` — local WebDAV server for the Windows redirector

### 7.1 The Windows WebDAV redirector, per version

Components: kernel `mrxdav.sys` (WebDAV mini-redirector, under RDBSS/MUP), user-mode `WebClient` service
(`webclnt.dll`, runs as LocalService), network provider `davclnt.dll` ("Web Client Network").

**Common registry parameters** (`HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters`, DWORD,
restart WebClient after changing; [IIS team blog, R. McMurray](https://blogs.iis.net/robert_mcmurray/webdav-redirector-registry-settings)):

| Value | Default | Relevance |
|---|---|---|
| `BasicAuthLevel` | 1 (Basic over SSL only; 0 = off; 2 = also non-SSL) | We never need to change it (7.4). |
| `FileSizeLimitInBytes` | 50,000,000 | Max file size the redirector transfers. Max settable 4,294,967,295 (0xFFFFFFFF), so **4 GiB − 1 is a hard cap** for WebDAV ([fast.io summary](https://fast.io/resources/webdav-file-size-limit/), [Druva](https://help.druva.com/en/articles/8807362-webdav-download-fails-with-file-size-exceeds-the-limit-error)). Error 0x800700DF when exceeded. |
| `FileAttributesLimitInBytes` | 1,000,000 | Max size of all properties of one collection in PROPFIND/PROPPATCH responses ([KB 912152](https://support.microsoft.com/kb/912152)). At ~330 bytes per compact entry, folders over ~3,000 entries fail at the default. |
| `LocalServerTimeoutInSec` | 15 | connect timeout for local servers |
| `SendReceiveTimeoutInSec` | 60 | timeout after a request is sent. **Response headers must arrive within 60 s**, including after a large PUT body. |
| `ServerNotFoundCacheLifeTimeInSec` | 60 | a server that once failed discovery is negatively cached for 60 s. **Our server must be listening before mapping.** |
| `SupportLocking` | 1 | redirector issues LOCK/UNLOCK |
| `AcceptOfficeAndTahoeServers` | 1 | irrelevant |
| `AuthForwardServerList` (REG_MULTI_SZ, Vista+) | absent | URLs to which default credentials are sent even if not intranet ([KB 956943](https://support.microsoft.com/kb/956943)). Not needed for `localhost`. |

**Installer action (`WEBDAV_TUNING`, C28; admin, opt-in checkbox, default on in the per-machine EXE,
property in the MSI)**: set **only** `FileSizeLimitInBytes = 0xFFFFFFFF` and
`FileAttributesLimitInBytes = 100,000,000`, record the original values and restore them on uninstall,
then restart WebClient. `BasicAuthLevel` and every other value are never touched. These are resource
limits, not authentication or security settings. Per-user setup has no HKLM access and skips the action;
it shows how to apply it (`shelldrive --installer-hook webdav-tune --apply`, elevated). The app works
without them, with the documented limits, and warns when it detects the defaults.

The requirement wording is amended (A1, A2): WebDAV needs no driver and is available where the WebClient
feature is present and not disabled (deprecated since November 2023, so Dokany is the primary backend on
Windows 7 SP1+); authentication on loopback is Negotiate/NTLM via SSPI plus a per-mount path token.

**Windows XP SP3 (x86)**
- WebClient + `mrxdav.sys` exist. The user-mode side uses WinINet. HTTPS is not supported by the XP
  redirector ([WsgiDAV client notes](https://wsgidav.readthedocs.io/en/latest/user_guide_access.html)),
  which is irrelevant for loopback.
- **Non-80 ports**: XP RTM, SP1 and SP2 have the bug "The redirector does not support HTTP URLs where a
  specific port number is specified". It is **not** listed for hotfix KB909423 (5.1.2600.2788), KB946026
  or **XP SP3 (5.1.2600.5512)** ([greenbytes redirector list](https://greenbytes.de/tech/webdav/webdav-redirector-list.html)).
  So XP SP3, our minimum, should handle `http://localhost:PORT/...`. Older community guidance saying "XP
  needs port 80" predates SP3. Verify on XP SP3 x86. **Fallback**: if mapping on a random port fails on
  XP, try binding `127.0.0.1:80` (usually free on desktop XP) and map without a port.
- **Mapping syntax on XP**: `WNetAddConnection2W` with
  `lpRemoteName = L"http://localhost:PORT/s-<token>"` and `lpProvider = L"Web Client Network"`.
  The `\\host@port\DavWWWRoot` UNC form is documented for `DavGetHTTPFromUNCPath`
  ([docs](https://learn.microsoft.com/windows/win32/api/davclnt/nf-davclnt-davgethttpfromuncpath))
  without version history. Verify whether XP accepts `\\localhost@PORT\DavWWWRoot\...`; use the http URL
  form on XP regardless.
- XP cannot map a server root ([WsgiDAV](https://wsgidav.readthedocs.io/en/latest/user_guide_access.html));
  we always map `/s-<token>`, so this is moot. The OPTIONS request to the server root must advertise
  DAV, or the redirector fails ([Hanselman](https://www.hanselman.com/blog/mappingconnecting-a-drive-letter-to-a-webdav-or-front-page-website)).
  We answer OPTIONS on `/`.
- The XP Explorer "Web Folders" (MSDAIPP, an Office/IE namespace extension) is not a drive and not used.
- WebClient start type on XP Pro: Automatic by default (verify; it is Disabled on Server 2003).
- Verify on XP: whether `FileSizeLimitInBytes` applies, and whether XP sends LOCK.

**Windows Vista / 7**
- WinHTTP-based. Credentials are sent automatically only to intranet hosts; a dotless name like
  `localhost` is intranet ([KB 941050](https://support.microsoft.com/kb/941050), [KB 943280](https://support.microsoft.com/kb/943280/)).
- UNC form `\\server[@SSL][@port]\path`; `DavWWWRoot` denotes the server root.
- Vista RTM had a broken Basic auth (domain prepended; greenbytes). Irrelevant: we do not use Basic.
- WebClient: Manual on Vista. On **Windows 7+ it is trigger-start**: an ETW event from the provider
  `Microsoft-Windows-WebdavClient-LookupServiceTrigger` (`{22B6D684-FA63-4578-87C9-EFFCBE6643C7}`)
  starts it. `davclnt.dll` writes this event when a DAV path is accessed, and **any non-elevated user**
  can write it ([SpecterOps](https://specterops.io/blog/2025/08/19/will-webclient-start/),
  [TrustedSec](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)).
  Service triggers exist only on 7/2008 R2+ ([MS docs](https://learn.microsoft.com/windows/win32/services/service-trigger-events)).

**Windows 8 / 8.1 / 10 / 11**
- Same model as 7. **The WebClient (WebDAV) service is deprecated** since November 2023: "isn't started
  by default", still present ([Microsoft deprecated features](https://learn.microsoft.com/windows/whats-new/deprecated-features)).
  As of the 2026-09 revision of that page it is deprecated but not removed. This is the single largest
  strategic risk for the WebDAV backend (section 12).
- NTLM (all versions) is deprecated since June 2024. NTLMv1 was removed in 11 24H2 / Server 2025, while
  NTLMv2 keeps working (same page). We use Negotiate, which picks the best available package (7.4).

**Windows Server**
- 2008 / 2008 R2 / 2012 / 2012 R2: WebClient comes with the **Desktop Experience** feature
  (`Install-WindowsFeature Desktop-Experience`, reboot).
- 2016+: the **WebDAV Redirector** feature (`Install-WindowsFeature WebDAV-Redirector`, reboot)
  ([Agilicus](https://www.agilicus.com/faq/enable-webclient-webdav-on-windows-server/),
  [SPGeeks](https://spgeeks.devoworx.com/add-desktop-experience-feature-on-windows-server-2012/)).
- Neither is installed by default. ShellDrive detects the missing `WebClient` service and offers the
  elevated command, or recommends Dokany, which is better on servers anyway.

### 7.2 Starting WebClient

`sd_webdav_ensure_client()`:
1. `OpenSCManager` / `OpenService(L"WebClient", SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG)`.
   Missing → `SD_WD_E_NO_CLIENT` with Server guidance (7.1).
2. Disabled → `SD_WD_E_CLIENT_DISABLED`. Offer elevation (`shelldrive diag --fix webclient`, C7,
   started via `ShellExecuteEx` "runas") to set start type Manual. We never change this silently.
3. Stopped: try `StartService` (works if the service DACL grants the user `SERVICE_START`; usually only
   admins). On ERROR_ACCESS_DENIED and Win7+, register the trigger provider GUID with `EventRegister` and
   `EventWrite` an event (the same mechanism `davclnt.dll` uses), then poll `QueryServiceStatus` for up to
   10 s. On XP/Vista with no permission → elevation prompt.
4. Running → OK. Mapping itself (`WNetAddConnection2`) also triggers it on 7+; step 3 just makes errors
   explicit and fast.

### 7.3 Listener

- One server per ShellDrive process (per-user agent); a separate one in the service for global WebDAV
  profiles (7.7). Each mount is a path prefix `/s-<token>/`: 130 bits from `RtlGenRandom` (XP+), base32,
  lowercase, 26 chars. No readable profile slug is put in the URL (C30); labels come from
  `_LabelFromReg` (below).
- Bind `127.0.0.1:0` (ephemeral port, which avoids Hyper-V excluded ranges), then the same port on `[::1]`
  if IPv6 is present (Vista+ may resolve `localhost` to ::1 first). If ::1 cannot take the same port,
  rebind both on a new port. Loopback-only listeners do not create Windows Firewall prompts (verify on
  XP SP3's firewall).
- **The mapping is not persistent** (`CONNECT_UPDATE_PROFILE` is not set). Ports change per start; the
  agent maps at logon. Stale `MountPoints2` entries from previous ports are cleaned.
- Host header MUST be `localhost:PORT`, `127.0.0.1:PORT` or `[::1]:PORT`, otherwise 400. This blocks DNS
  rebinding from browsers.
- No CORS headers are ever sent. Cross-origin PUT/DELETE/PROPFIND need a preflight, which fails; simple
  GETs from a web page cannot know the token.
- HTTP/1.1 persistent connections are required (connection-based NTLM). Idle timeout 120 s; max 64
  connections per server.
- Mapping (Vista+): `WNetAddConnection2W` with `lpRemoteName = L"\\\\localhost@PORT\\DavWWWRoot\\s-<token>"`,
  `dwType = RESOURCETYPE_DISK`, and the drive letter. XP: the http form (7.1).
- Drive label: write `_LabelFromReg` = profile name under
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\##localhost@PORT#DavWWWRoot#s-<token>`.
  Otherwise Explorer shows the token. Remove it at unmount.

### 7.4 Authentication and multi-user isolation

Options evaluated:

| Option | Verdict |
|---|---|
| Basic over http | Needs `BasicAuthLevel = 2` machine-wide (default 1 allows Basic over SSL only; [MS archive blog](https://learn.microsoft.com/en-us/archive/blogs/saurabh_singh/some-info-around-webdav-content-access-issues)). That lowers security for every WebDAV server. **Rejected.** |
| Basic over https on loopback | Needs a self-signed cert in the user's trusted root store (a security-sensitive, UAC-prompted change), XP's redirector has no SSL, and it costs TLS overhead. **Rejected.** |
| Unguessable path token | Works everywhere and needs no settings. The token is a bearer secret: any local process of **any** user that learns it (logs, command lines, the `net use` output of that user) gets access. **Necessary but not sufficient alone.** |
| Negotiate/NTLM via SSPI on loopback | The redirector sends the logged-on user's default credentials to intranet hosts (dotless `localhost`) without prompting (KB 941050/943280). The server runs `AcceptSecurityContext` (package "Negotiate", which also accepts raw "NTLM" tokens), then `QuerySecurityContextToken` → `TokenUser`, and compares to the owner SID. The OS cryptographically proves the caller's identity, so this handles **multi-user isolation**. **Chosen**, together with the token. |

Design:
- All requests except `OPTIONS` require auth. The first request gets
  `401` + `WWW-Authenticate: Negotiate` + `WWW-Authenticate: NTLM`. The SSPI context is per TCP
  connection. After success the connection stays authenticated (no per-request re-auth; this is the IIS
  `authPersistNonNTLM`-style behavior).
- Allowed: the mount owner SID (per-user servers); for the service server, members of the profile's
  allowed group (7.7). Anything else → 403.
- **Elevated attach (C26)**: an elevated process of the same user (`--elevated-view`, 03 §1.7.2) maps the
  agent's server in its own logon session. The linked elevated token carries the **same user SID**, so
  the Negotiate SID check passes unchanged; the path token remains the per-mount secret. No Basic and no
  separate credential: `mount.attach_info` returns only the UNC with the token.
- Token prefix check happens **before** auth on unknown prefixes (404, no challenge), so nothing reveals
  which prefixes exist. `PROPFIND /` (depth 0/1) returns the root collection with **no members**.
- **Fallback when SSPI auth is not possible**. Example: policy "Restrict NTLM: Incoming NTLM traffic =
  Deny all" while Kerberos is unavailable for `HTTP/localhost`. Detect it with a self-test at mount time:
  a WinHTTP request with `WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW` to our own server. If it fails, a
  per-user mount may run **token-only** after a one-time warning ("other local users who obtain this
  address could access the drive"). Global WebDAV mounts refuse token-only.
- If the redirector ever prompts for credentials, the profile is flagged and switched to token-only on
  the next start, with a notice. A prompt means autologon is disabled by policy.
- Verify on each OS: no credential prompt, `TokenUser` equals the interactive user, and behavior under a
  configured system proxy (WinHTTP proxy bypass for `<local>`).

### 7.5 Methods

All paths are percent-decoded as UTF-8, mapped via 1.2, and resolved under the mount prefix. Responses
use `Content-Length` (multistatus bodies are built in memory, bounded by `FileAttributesLimitInBytes`
headroom). Request bodies with `Transfer-Encoding: chunked` and `Expect: 100-continue` are supported.

| Method | Implementation |
|---|---|
| `OPTIONS` (any path, unauth OK) | `200`, `DAV: 1, 2`, `MS-Author-Via: DAV`, `Allow: OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK` (write methods omitted on read-only mounts), `Content-Length: 0`. |
| `PROPFIND` | Depth `0` or `1` (missing header = infinity → `403` with `<D:propfind-finite-depth/>`). Bodies: allprop (also an empty body), `prop`, `propname`. Live props: `resourcetype`, `getcontentlength`, `getlastmodified` (RFC 1123), `creationdate` (RFC 3339), `getetag` (`"<mtime hex>-<size hex>"`), `getcontenttype` (`application/octet-stream`; `httpd/unix-directory` not sent), `supportedlock`, `lockdiscovery`, `displayname` only when requested. MS props (namespace `urn:schemas-microsoft-com:`): `Win32FileAttributes` (8 hex digits), `Win32CreationTime`, `Win32LastAccessTime`, `Win32LastModifiedTime` (RFC 1123). On the mount root: `quota-available-bytes` / `quota-used-bytes` (RFC 4331) from statvfs, which Explorer uses for free space. Unknown requested props → `404` propstat. Entries are compact (no pretty printing, single namespace prefixes `D:` and `Z:`), to stay within `FileAttributesLimitInBytes`. |
| `PROPPATCH` | `Win32CreationTime` (ignored), `Win32LastAccessTime` / `Win32LastModifiedTime` → `sd_vfs_set_times`, `Win32FileAttributes` → `sd_vfs_set_winattrs`. Any other property → reported `200` and discarded (no dead-property store; failing breaks the redirector's create sequence). Read-only mount → `403`. |
| `GET` / `HEAD` | Open with `FILE_OPEN`, read through vfs read-ahead, stream. `Range: bytes=a-b` (single range) → `206` + `Content-Range`. Multi-range → `200` full. Unsatisfiable → `416`. `If-Range` / `If-None-Match` / `If-Modified-Since` use the ETag and mtime. Response headers are sent as soon as the attrs are known, so the 60 s `SendReceiveTimeoutInSec` never trips on large files. GET on a collection → `200` with a minimal HTML index (helps debugging only). |
| `PUT` | `FILE_OVERWRITE_IF` (`If-None-Match: *` → `FILE_CREATE`). The **body is streamed into vfs writes** as it arrives, with TCP backpressure from a bounded window (16 MiB, in both write modes: the PUT response is the point where the redirector learns the outcome, 4.4). The final drain and fsync happen right after the last byte, so the response follows within at most one window (≤ 16 MiB) of acknowledgements, well inside the 60 s timeout. `201` if created, `204` if replaced. Lock token enforcement (below). Content length > 0xFFFFFFFF is impossible from the redirector. Option `atomic_put` (default off): write to `.<name>.sd-<rand>` and `posix-rename` over the target, with the original mode copied. |
| `DELETE` | 2.4. Files: remove. Collections: recursive, `207` on partial failure. |
| `MKCOL` | `mkdir`. Body present → `415`. Parent missing → `409`. Exists → `405`. |
| `MOVE` | `Destination` (absolute URI; must have the same authority and token prefix, else `502`), `Overwrite: T` (default) → replace semantics, `F` → no-replace (`412` if exists). `201` new / `204` replaced. Directories in one rename. |
| `COPY` | Depth `0` / `infinity`. Files: `copy-data` SFTP extension when advertised (server-side), else stream read → write through the vfs. Collections: recursive. Same `Overwrite` rules. |
| `LOCK` | Exclusive and shared write locks, `Timeout: Second-n` capped at 3600, `Infinite` → 3600. Lock token `opaquelocktoken:<uuid>`. LOCK on an unmapped URL creates an empty file (RFC 4918 locked empty resource) → `201`. Refresh via `If` header with no body. Depth 0 only for files; depth infinity on collections is accepted and recorded. Read-only mount → `403` (Office then opens read-only). |
| `UNLOCK` | `Lock-Token` header → `204`; unknown → `409`. |
| others (`POST`, `PATCH`, `SEARCH`, `REPORT`, ...) | `405` / `501` |

**Lock manager**: in memory per server. Locks are keyed by vfs node, so renames carry them. While a
resource is locked, mutating requests without a matching token in `If:` → `423 Locked`. Locks are
**not** propagated to SFTP (there is nothing to propagate to). They do take a vfs share registration
(deny-write) so that a Dokany mount of the same remote path in this process respects Office's lock.
Expired locks are swept every 30 s.

**Error mapping** (`sd_vfs_status` → HTTP): NOT_FOUND / PATH_NOT_FOUND 404 (409 for a missing parent on
PUT/MKCOL/MOVE), EXISTS 405/412, ACCESS_DENIED 403, READ_ONLY 403, SHARING / LOCKED 423, NO_SPACE 507,
DISCONNECTED 503 + `Retry-After`, TIMEOUT 504, STALE 409, NOT_EMPTY 409, TOO_LARGE 413, INVALID_NAME 400,
other 500. This table and the NTSTATUS table in 8 are normative; 01 §10.9's hints are superseded (C24).

### 7.6 Redirector behaviors that shape the server

- **Whole-file local caching.** The redirector downloads the complete file into its local cache before a
  data open completes, and uploads the whole file with one PUT when the last handle closes (consistent
  community reports, e.g. [Total Commander forum](https://www.ghisler.ch/board/viewtopic.php?p=361736);
  verify with a capture). Consequences:
  - opening a 2 GB file takes the full download time; random access to big files (VM images, databases)
    is impractical;
  - a 1-byte change uploads the full file;
  - the system drive temporarily holds a copy. Verify the location (believed to be the LocalService
    profile's `TfsStore`) and whether it is per-user protected;
  - the 4 GiB − 1 hard cap (7.1).

  These make WebDAV the compatibility backend, not the performance backend.
- Typical create sequence (Vista+): `PUT` (0 bytes) → `PROPPATCH` (Win32 times/attrs) → `LOCK` → ... →
  `PUT` (content) → `PROPPATCH` → `UNLOCK`. Every step must succeed quickly.
- **Explorer**: heavy `PROPFIND depth 1` on every folder view, and probes for `desktop.ini`,
  `Thumbs.db`, `folder.jpg` (fast 404 via 4.1 probe suppression). **Thumbnails and property handlers
  force full downloads** of media files on WebDAV. Optional profile flag `offline_hint_over_mb` (default
  off) sets `FILE_ATTRIBUTE_OFFLINE` in `Win32FileAttributes` for files above N MB. Explorer then skips
  thumbnail extraction, at the cost of backup tools that skip offline files. Decision D22: kept as a
  profile option, **default off**. Dokany mounts never set `OFFLINE`.
- **Office**: probes with `OPTIONS` and may try FrontPage RPC (`/_vti_bin/`, `/_vti_inf.html`) or
  SharePoint endpoints. We answer `404` immediately so it falls back to plain DAV. It needs `LOCK`
  advertised in `Allow` and `supportedlock` in PROPFIND, or it opens documents read-only
  ([Micro Focus KB](https://support.microfocus.com/kb/doc.php?id=7001922)). Save = write temp, delete
  original, rename temp: this exercises MOVE + DELETE with locks and must keep working under 423 rules
  (the locks are Office's own).
- Large folders: keep each PROPFIND entry at ~330 bytes; warn when a folder exceeds
  `FileAttributesLimitInBytes / 330` entries and the limit is at its default.

### 7.7 Global (service) WebDAV mounts (D11)

Dokany global drives (6.4) remain the primary path for `scope = service` profiles: `backend = auto`
picks Dokany wherever it is available. Global WebDAV drives are **attempted** for systems without Dokany
(XP, Server 2003, Vista, unpatched Win7, ARM32) and for profiles forced to `webdav`. Amendment A4 as
rewritten by D11: global drives are provided by Dokany; WebDAV global drives exist on the OS versions
where the lab spike below passes, and elsewhere WebDAV service profiles are attached per user at logon.
This replaces C27's "reject service profiles with `backend = webdav`".

**Common part (all mechanisms)**
- The service (`shelldrive-host.exe service`, LocalSystem) hosts one WebDAV server (7.3) and the SFTP
  pool for each such profile: one remote identity shared by all users, shown in the UI.
- The listener port is chosen once per service start and kept for its lifetime; the service records it
  in its state so that stale mappings from a previous start can be removed.
- **Access control: SSPI with the service as the server.** The service calls `AcceptSecurityContext`
  ("Negotiate") under LocalSystem, then `QuerySecurityContextToken`. The resulting token is used only
  for identification (`TokenUser`, `CheckTokenMembership` against the profile's `service_access` SID list, 03 §3.4.1; default
  `BUILTIN\Users` (`S-1-5-32-545`), configurable to any users or groups); the service never impersonates it. Rejected always:
  anonymous and `Guest` tokens, `NT AUTHORITY\NETWORK SERVICE`/`LOCAL SERVICE` unless listed in the
  allowed group, and `SYSTEM` unless `allow_system` is on. Results are cached per (logon LUID, SID) for
  60 s, like 6.7.
- **The path token is not a secret here.** A global mapping exposes the UNC (with the token) to every
  user (`net use`, `QueryDosDevice`). Security rests entirely on the SSPI check; token-only is never
  allowed for service servers (7.4), and the token only keeps browsers and drive-by requests out.
- **Per-request identity.** The SSPI context is per TCP connection (7.4). The service server must never
  serve user B on a connection authenticated as user A. Lab criterion G2 below checks that the
  redirector never shares an authenticated connection across logon sessions. If it does on some OS, the
  service server switches to `Connection: close` after every response on that OS (per-request
  authentication, about 3 extra loopback round trips per request), and the cost is measured against the
  targets in 11.
- Read-only and write-mode settings are per profile as usual; write-through is strongly recommended for
  shared drives (the `write_failed` notification of write-behind would reach only the agent sessions
  that are subscribed, 03).

**Mechanism A — system-wide mapping by LocalSystem (XP / Server 2003).** On XP and 2003, a drive letter
mapped by a LocalSystem service lands in the global DOS device namespace and is visible to all users
(the documented XP/2003 behavior cited in D11; verify). The service calls `WNetAddConnection2W` with the
http form (7.1) in its own context. Open question for the lab: whether the redirector then authenticates
accesses from user sessions as the accessing user (needed for G2) or as the machine/SYSTEM, in which case
per-user access control is impossible and the mechanism fails G2.

**Mechanism B — global symbolic link to the UNC (Vista+, and XP/2003 if A fails G2).** The service creates
a global drive letter with `DefineDosDeviceW(DDD_RAW_TARGET_PATH, L"Global\\Z:",
L"\\Device\\Mup\\localhost@PORT\\DavWWWRoot\\s-<token>")` (XP uses the `\Device\Mup` form the http
mapping resolves to; verify), creating no redirector connection of its own. Each user's first access is
then an implicit UNC connection made by that user's logon session with that user's default credentials,
so the SSPI check sees the accessing user. Expected limitations to measure: Explorer may show the drive
as "Disconnected network drive" or without a label (`_LabelFromReg` is per user; the agent, if running,
writes it at logon), and users cannot "Disconnect" a global link (only the service removes it).

**Lab spike (early M5, go/no-go per OS).** Systems: XP SP3 x86, Server 2003 SP2, Vista SP2, 7 SP1
(x86 and x64), 8.1, 10 22H2, 11 24H2+, Server 2008 R2, 2012 R2, 2016, 2019, 2022, 2025; each with two
standard users, one admin, RDP and fast user switching. For each OS and mechanism, record:

| # | Criterion | Go requires |
|---|---|---|
| G1 | Visibility | The drive appears in every interactive session (console, RDP, FUS) in Explorer and `cmd` without any per-user action, and survives logoff/logon of other users. |
| G2 | Identity | The server sees each accessing user's own SID (not SYSTEM, machine account or anonymous), without a credential prompt, and two concurrent users never share an authenticated TCP connection (or the per-request fallback keeps PROPFIND depth 1 of 1,000 entries ≤ 2× the per-user figure in 11). A user outside the allowed group gets "access denied", not data. |
| G3 | Robustness | WebClient restart, service restart (mapping recreated, stale one removed) and sleep/resume leave a working drive within 30 s; no orphaned drive letter blocks the letter afterwards. |
| G4 | No settings | No change to `BasicAuthLevel`, `AuthForwardServerList` or other security settings; no per-user elevation. |
| G5 | Function | Copy in/out (1 GiB with matching SHA-256), rename, delete, Office save with locks, as two users concurrently; large-folder PROPFIND within the `FileAttributesLimitInBytes` the installer set. |
| G6 | Before logon (reported, not required) | Access from a LocalSystem / NetworkService process before any interactive logon. Recorded as a capability flag per OS; the UI states "available before logon" only where G6 passes. |

Go for an OS = G1–G5 pass for at least one mechanism; the passing mechanism (A preferred on XP/2003,
B elsewhere) is recorded in a table compiled into `sd_webdav` keyed by OS version. The host's setting
`settings.ini [service] webdav_global_mode = auto | system | link | attach` (03 §1.3) names the same
choices: `system` = mechanism A, `link` = mechanism B, `attach` = the per-user fallback below; `auto` uses
the compiled-in table. **No-go** → that OS
uses the per-user attach below. The spike result is recorded in this section before M5 ends.

**Fallback: per-user attach at logon (no-go OSes, and whenever the system-wide mapping fails at run time).**
- The per-user agent, started at logon (Run key, C11), asks the service over its pipe for the attach
  information of each global WebDAV profile the user is allowed to use (a read-only service IPC call,
  `mount.attach_info` for service mounts; this is an attach, not a data proxy, so it does not contradict
  03 §2.6's "agent does not proxy"; 03 adds the call).
- The agent maps the returned UNC with `WNetAddConnection2W` in the user's logon session and writes the
  label (7.3). The SSPI group check on the service server is the access control.
- Elevated sessions attach the same way (C26).
- Not available before logon and not to session-0 processes other than through the UNC path.

---

## 8. `sd_vfs` public interface (sketch)

```c
/* sd_vfs.h */
typedef enum sd_vfs_status {
    SD_VFS_OK = 0,
    SD_VFS_E_NOT_FOUND, SD_VFS_E_PATH_NOT_FOUND, SD_VFS_E_EXISTS, SD_VFS_E_ACCESS_DENIED,
    SD_VFS_E_READ_ONLY, SD_VFS_E_SHARING, SD_VFS_E_DELETE_PENDING, SD_VFS_E_CANNOT_DELETE,
    SD_VFS_E_NOT_EMPTY, SD_VFS_E_IS_DIR, SD_VFS_E_NOT_DIR, SD_VFS_E_INVALID_NAME,
    SD_VFS_E_NAME_TOO_LONG, SD_VFS_E_NO_SPACE, SD_VFS_E_QUOTA, SD_VFS_E_TOO_LARGE,
    SD_VFS_E_DISCONNECTED, SD_VFS_E_STALE, SD_VFS_E_TIMEOUT, SD_VFS_E_UNSUPPORTED,
    SD_VFS_E_NO_MEMORY, SD_VFS_E_IO, SD_VFS_E_CANCELLED, SD_VFS_E_END_OF_FILE
} sd_vfs_status;

#define SD_VFS_MAX_CONN 4

typedef enum { SD_VFS_WRITE_THROUGH = 0 /* default */, SD_VFS_WRITE_BEHIND = 1 } sd_vfs_write_mode;

typedef struct sd_vfs_options {
    UINT32 struct_size;
    const char *remote_root;            /* bytes; NULL = home */
    BOOL  read_only, hide_dotfiles, map_readonly, case_sensitive_view, show_special, allow_system;
    int   remote_case;                  /* AUTO/SENSITIVE/INSENSITIVE */
    int   symlinks;                     /* SD_SYMLINK_FOLLOW / SD_SYMLINK_HIDE (no reparse value, 6.9) */
    UINT  umask, remote_codepage;       /* 0 = UTF-8 (stage 1 of 1.2) */
    UINT  attr_ttl_ms, dir_ttl_ms, neg_ttl_ms; int open_revalidate_ms;
    UINT  max_readahead;
    sd_vfs_write_mode write_mode;       /* profile write_mode (4.4) */
    UINT  wb_window, wb_window_mount;   /* write-behind only */
    BOOL  fsync_on_flush;
    UINT  offline_wait_ms, reconnect_grace_ms;   /* grace: write-behind only */
    UINT  request_timeout_ms;           /* 25000 Dokany, 50000 WebDAV (5.7) */
    UINT  stripe_min_file;              /* default 8 MiB (5.6) */
    UINT  disk_cache_mb; const WCHAR *disk_cache_dir;   /* dir chosen by the host (C12) */
    UINT  offline_hint_over_mb;         /* WebDAV only; 0 = off (D22) */
    const WCHAR *volume_fs_name;        /* Dokany; NULL = L"NTFS" (D23) */
    const WCHAR *volume_label, *offline_label_suffix;  /* localized by the host (C45) */
    PSID  owner_sid;                    /* mount owner, for SD synthesis and isolation */
} sd_vfs_options;

typedef struct sd_vfs_identity {        /* section 3.4; internal state, filled from server_info.identity
                                           and confirmed by the first created object */
    BOOL uid_known, definitive; UINT32 uid, gid;
    const UINT32 *groups; UINT32 ngroups;   /* only with identity_probe = exec */
} sd_vfs_identity;

typedef struct sd_vfs        sd_vfs;
typedef struct sd_vfs_handle sd_vfs_handle;

typedef enum {
    SD_VFS_EV_CHANGE,           /* path, new_path, is_dir: forwarded to DokanNotify* */
    SD_VFS_EV_WRITE_FAILED,     /* path, bytes, status: host raises write_failed (C45) */
    SD_VFS_EV_DELETE_FAILED,    /* path, status (2.4) */
    SD_VFS_EV_STATE,            /* connected / disconnected / failed (session = primary connection) */
    SD_VFS_EV_IDENTITY,         /* uid learned or changed (3.4) */
    SD_VFS_EV_NOTICE            /* case collisions, pool shrink, ...: English log text + code */
} sd_vfs_event_kind;
typedef struct sd_vfs_event {
    sd_vfs_event_kind kind; int change_kind; const WCHAR *path, *new_path; BOOL is_dir;
    UINT64 bytes; sd_vfs_status status; UINT32 conn_index /* NOTICE about a pool member */; const char *code;
} sd_vfs_event;
typedef void (*sd_vfs_event_cb)(void *ctx, const sd_vfs_event *ev);  /* called on vfs threads, no vfs lock held */

/* One session per mount, whatever its pool size (5.6, 01 §10.9); it stays owned by sd_mount. The
   identity comes from server_info.identity on every READY_INFO (3.4); there is no separate setter. */
sd_vfs_status sd_vfs_mount(struct sd_sftp_session *s, const sd_vfs_options *o,
                           sd_vfs_event_cb cb, void *cb_ctx, sd_vfs **out);
/* host control thread only (5.4): */
void          sd_vfs_quiesce(sd_vfs *v, DWORD budget_ms);  /* block new opens, drain writes */
void          sd_vfs_unmount(sd_vfs *v);

/* create/open; kernel-style disposition and options (FILE_* from ntifs.h, duplicated in our header) */
sd_vfs_status sd_vfs_create(sd_vfs *v, const WCHAR *path, UINT32 access, UINT32 share,
                            UINT32 disposition, UINT32 create_options, UINT32 win_attrs,
                            sd_vfs_handle **h, BOOL *existed, BOOL *is_dir);
sd_vfs_status sd_vfs_cleanup(sd_vfs_handle *h, BOOL delete_pending);
void          sd_vfs_close(sd_vfs_handle *h);

sd_vfs_status sd_vfs_read (sd_vfs_handle *h, UINT64 off, void *buf, UINT32 len, UINT32 *got);
sd_vfs_status sd_vfs_write(sd_vfs_handle *h, UINT64 off /* SD_VFS_EOF */, const void *buf,
                           UINT32 len, UINT32 *done, BOOL paging_io);
sd_vfs_status sd_vfs_flush(sd_vfs_handle *h);
sd_vfs_status sd_vfs_truncate(sd_vfs_handle *h, UINT64 size);

typedef struct sd_vfs_info {             /* backend-neutral stat for Windows */
    UINT32 win_attrs; UINT64 size, alloc, file_id;
    FILETIME ctime, atime, mtime;  sd_vfs_attr posix;
} sd_vfs_info;
sd_vfs_status sd_vfs_getattr(sd_vfs_handle *h, sd_vfs_info *out);
sd_vfs_status sd_vfs_stat_path(sd_vfs *v, const WCHAR *path, sd_vfs_info *out);  /* WebDAV PROPFIND depth 0 */
sd_vfs_status sd_vfs_set_winattrs(sd_vfs_handle *h, UINT32 attrs);
sd_vfs_status sd_vfs_set_times(sd_vfs_handle *h, const FILETIME *c, const FILETIME *a, const FILETIME *w);

typedef BOOL (*sd_vfs_dirent_cb)(void *ctx, const WCHAR *name, const sd_vfs_info *info); /* FALSE = stop */
sd_vfs_status sd_vfs_readdir(sd_vfs_handle *h, sd_vfs_dirent_cb cb, void *ctx);

sd_vfs_status sd_vfs_can_delete(sd_vfs_handle *h);
sd_vfs_status sd_vfs_delete_path(sd_vfs *v, const WCHAR *path, BOOL recursive);   /* WebDAV */
sd_vfs_status sd_vfs_rename(sd_vfs_handle *h, const WCHAR *new_path, BOOL replace);
sd_vfs_status sd_vfs_rename_path(sd_vfs *v, const WCHAR *from, const WCHAR *to, BOOL replace);
sd_vfs_status sd_vfs_copy_path(sd_vfs *v, const WCHAR *from, const WCHAR *to, BOOL replace, BOOL recursive);

typedef struct sd_vfs_statfs { UINT64 total, free, avail; BOOL known; } sd_vfs_statfs;
sd_vfs_status sd_vfs_statfs_get(sd_vfs *v, sd_vfs_statfs *out);

sd_vfs_status sd_vfs_get_sd(sd_vfs_handle *h, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd,
                            ULONG len, ULONG *needed);
sd_vfs_status sd_vfs_set_sd(sd_vfs_handle *h, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd);

/* Diagnostics */
typedef struct sd_vfs_conn_stats { UINT32 state, generation, srtt_ms; UINT64 bytes_rd, bytes_wr,
                                   inflight_max, reconnects; } sd_vfs_conn_stats;
typedef struct sd_vfs_stats { UINT64 ops[32], rtts[32], cache_hits, cache_misses, bytes_rd, bytes_wr,
                              inflight_max, reconnects, write_failed;
                              UINT32 nconn; sd_vfs_conn_stats conn[SD_VFS_MAX_CONN]; } sd_vfs_stats;
void sd_vfs_get_stats(sd_vfs *v, sd_vfs_stats *out);
void sd_vfs_refresh(sd_vfs *v, const WCHAR *subtree);

/* Mapping tables, one per backend */
NTSTATUS sd_vfs_to_ntstatus(sd_vfs_status s);       /* in sd_dokan */
int      sd_vfs_to_http(sd_vfs_status s, int method); /* in sd_webdav */
```

NTSTATUS mapping (in `sd_dokan`): NOT_FOUND → `STATUS_OBJECT_NAME_NOT_FOUND`, PATH_NOT_FOUND →
`STATUS_OBJECT_PATH_NOT_FOUND`, EXISTS → `STATUS_OBJECT_NAME_COLLISION`, ACCESS_DENIED →
`STATUS_ACCESS_DENIED`, READ_ONLY → `STATUS_MEDIA_WRITE_PROTECTED`, SHARING → `STATUS_SHARING_VIOLATION`,
DELETE_PENDING → `STATUS_DELETE_PENDING`, CANNOT_DELETE → `STATUS_CANNOT_DELETE`, NOT_EMPTY →
`STATUS_DIRECTORY_NOT_EMPTY`, IS_DIR → `STATUS_FILE_IS_A_DIRECTORY`, NOT_DIR → `STATUS_NOT_A_DIRECTORY`,
INVALID_NAME → `STATUS_OBJECT_NAME_INVALID`, NAME_TOO_LONG → `STATUS_NAME_TOO_LONG`, NO_SPACE →
`STATUS_DISK_FULL`, QUOTA → `STATUS_DISK_QUOTA_EXCEEDED`, TOO_LARGE → `STATUS_FILE_TOO_LARGE`,
DISCONNECTED → `STATUS_CONNECTION_DISCONNECTED`, STALE → `STATUS_FILE_INVALID`, TIMEOUT →
`STATUS_IO_TIMEOUT`, UNSUPPORTED → `STATUS_NOT_SUPPORTED`, NO_MEMORY → `STATUS_INSUFFICIENT_RESOURCES`,
END_OF_FILE → `STATUS_END_OF_FILE`, IO → `STATUS_UNEXPECTED_IO_ERROR`.

**`sd_err` → `sd_vfs_status` (C13).** One table in `sd_vfs`, generated from the master error table in
`sd_base` and checked by a unit test that covers every enum value (00 §4):

| `sd_err` (01) | `sd_vfs_status` |
|---|---|
| `SD_OK` | `SD_VFS_OK` |
| `SD_E_EOF` | `SD_VFS_E_END_OF_FILE` (reads: short read, 6.5) |
| `SD_E_NOT_FOUND` | `SD_VFS_E_NOT_FOUND`, or `PATH_NOT_FOUND` when the parent is not known to exist |
| `SD_E_ACCESS_DENIED`, `SD_E_LOCK_CONFLICT` | `SD_VFS_E_ACCESS_DENIED` |
| `SD_E_EXISTS` | `SD_VFS_E_EXISTS` |
| `SD_E_NOT_EMPTY` | `SD_VFS_E_NOT_EMPTY` |
| `SD_E_NOT_A_DIRECTORY` / `SD_E_IS_A_DIRECTORY` | `SD_VFS_E_NOT_DIR` / `SD_VFS_E_IS_DIR` |
| `SD_E_NO_SPACE` / `SD_E_QUOTA` | `SD_VFS_E_NO_SPACE` / `SD_VFS_E_QUOTA` |
| `SD_E_READ_ONLY` | `SD_VFS_E_READ_ONLY` |
| `SD_E_INVALID_NAME`, `SD_E_LINK_LOOP` | `SD_VFS_E_INVALID_NAME` / `SD_VFS_E_NOT_FOUND` (follow mode, 6.9) |
| `SD_E_NAME_TOO_LONG` | `SD_VFS_E_NAME_TOO_LONG` |
| `SD_E_UNSUPPORTED` | `SD_VFS_E_UNSUPPORTED` (the vfs picks its fallback first, e.g. rename 2.5) |
| `SD_E_DISCONNECTED`, `SD_E_SHUTDOWN`, `SD_E_AUTH_REQUIRED` | `SD_VFS_E_DISCONNECTED` |
| `SD_E_STALE_HANDLE` | handled internally (re-open, 5.3); `SD_VFS_E_STALE` only after a failed identity check |
| `SD_E_TIMEOUT` | `SD_VFS_E_TIMEOUT` |
| `SD_E_CANCELLED` | `SD_VFS_E_CANCELLED` |
| `SD_E_BUSY` | never surfaced: backpressure (4.3, 4.4) |
| `SD_E_NO_MEMORY` | `SD_VFS_E_NO_MEMORY` |
| `SD_E_INVALID_PARAM`, `SD_E_FAILURE`, `SD_E_PROTOCOL`, anything else | `SD_VFS_E_IO` (raw server code and message logged) |

**`SSH_FX_FAILURE` is refined by `sd_sftp`, not here (C14).** 01's `SD_SFTP_OPT_REFINE_ERRORS` (on)
already turns `FAILURE` into EXISTS / NOT_EMPTY / IS_A_DIRECTORY / NOT_A_DIRECTORY / NO_SPACE with its own
probes, and passes through v4–v6 status codes that some servers send on v3. `sd_vfs` maps the refined
codes only and sends no probes of its own. The single vfs-side rule kept: `RENAME` with replace onto a
non-empty directory → `SD_VFS_E_ACCESS_DENIED` (`STATUS_ACCESS_DENIED`, as NTFS does), whatever code the
server returned.

---

## 9. Requirements on `sd_sftp`

Numbered so the two designs stay reconciled. "MUST" = blocking for this layer. Each item carries the
resolution agreed in `00-integration-review.md` §3.1 (and C13–C18) and where 01 now meets it (reconciled
2026-10-24; 01 §10 is the contract text and wins on details). Names are 01's (C13).

| R | Requirement (summary) | Resolution / where it is met |
|---|---|---|
| R1 (MUST) | Async, thread-safe submission; completion off-thread, never inline from the submit call; callbacks may chain async requests. | **Met** (01 D2, §10.8). Completions run on the I/O thread of the connection that carried the request; with a pool > 1 completions of one session may run concurrently (01 §10.8 item 2). The vfs obeys 00 §4.1 rule 1 there (5.4). |
| R2 (MUST) | Operation set: `open` (READ\|WRITE\|APPEND\|CREAT\|TRUNC\|EXCL), `close`, `read` into the caller buffer, `write`, `lstat`, `stat`, `fstat`, `setstat`, `fsetstat`, `opendir`, `readdir`, `remove`, `mkdir`, `rmdir`, `rename`, `realpath`, `readlink`, `symlink` with the OpenSSH argument-order quirk hidden. | **Met** (01 §10.5). |
| R3 (MUST first three, SHOULD rest) | Extensions with capability query: `posix-rename`, `statvfs`/`fstatvfs`, `fsync`, `limits`, `hardlink`, `lsetstat`, `copy-data`, `home-directory`, `expand-path`, `users-groups-by-id`. | **Met.** `server_info.ext` from `SD_SFTP_EV_READY_INFO`, re-read on every generation, and `sd_sftp_has_ext()` (01 §10.3). |
| R4 (MUST) | Limits exposed (max read, write, packet, open handles; conservative defaults without `limits@openssh.com`). | **Met** for the values. Chunking (C15): 01 keeps splitting oversize requests (harmless); `sd_vfs` issues chunks ≤ `max_read`/`max_write` itself, so each of its submissions is exactly one wire request, and 01 documents that guarantee. |
| R5 (MUST) | ≥ 64 requests in flight per channel, bounded queueing, out-of-order completion allowed. | **Met** with an addition: 01 caps its pending FIFO (`max_queued_reqs`) and returns `SD_E_BUSY` beyond it. The vfs treats `SD_E_BUSY` as backpressure (4.3, 4.4). `close` is issued only after all writes on that handle completed (01 also queues it behind them). |
| R6 (SHOULD) | Reads into the caller-supplied buffer; short reads report the length; EOF distinct. | **Met** (`SD_E_EOF`, `u.read.eof`). |
| R7 (MUST) | Neutral error enum, raw server status code and message. | **Met** with 01's names (`sd_err`, `SD_E_*`; C13). Mapping table in 8. `SSH_FX_FAILURE` refinement is 01's (C14). |
| R8 (MUST) | State events; on loss every outstanding request completes promptly. | **Met** (01 §10.4 event ordering). Detection latency is covered by R15/C16. |
| R9 (MUST) | Generations; stale handles fail locally; wait-ready primitive. | **Met**: `generation`, `SD_E_STALE_HANDLE`, `sd_sftp_file_reopen`, and `SD_SFTP_REQ_WAIT_READY` (+ `timeout_ms`) in place of `wait_connected()`. |
| R10 (MUST) | Full v3 ATTRS with presence mask, 64-bit times, extended pairs passed through. | **Met**: `sd_sftp_attrs.ext` / `ext_count`, valid during the completion only (01 §10.3). |
| R11 (MUST) | Raw byte names, no conversion inside `sd_sftp`. | **Met**; 01's `sd_name_to_wide/from_wide` is stage 1 of 1.2 (C23). |
| R12 (MUST) | Server identity: banner, SFTP version, extension list with versions, host key fingerprint, quirk flags. | **Met**: `server_info.ext_list` (every announced extension) and `SD_SFTP_QUIRK_WIN_DRIVE_PATHS` (01 §10.3). |
| R13 (SHOULD) | Remote uid and gids. | **Met (D10 / C18)**: no exec by default; `server_info.identity` gives the home owner, and the vfs confirms it from the first object it creates (3.4). With `identity_probe = exec`, `sd_sftp` runs the probe itself (`SD_SFTP_OPT_IDENTITY_EXEC`, over `sd_ssh_channel_open_exec()`, 01 §11). `users-groups-by-id` for names only. |
| R14 (SHOULD) | Metadata not queued behind bulk data. | **Resolved by D19 / C17**: two SFTP channels per connection, channel 0 = "meta" (path ops, opendir/readdir, attribute-only opens), channel 1 = "bulk" (data handles); with one channel (auto-degrade) 01's scheduler serves the meta class first. SSH channel window ≥ 2 MiB with timely adjusts. |
| R15 (MUST) | Cancellation and per-request deadline; a timeout triggers a health check, not a teardown. | **Resolved by C16**: `sd_vfs` passes `timeout_ms` on every request (25 s Dokany, 50 s WebDAV; 5.7). 01 (§4.6, §10.5): on any request timeout, an immediate `keepalive@openssh.com`, connection declared dead if unanswered within `min(5 s, 3 × srtt)`. `sd_sftp_cancel` discards late replies. |
| R16 (SHOULD) | RTT and throughput estimates. | **Met**: `sd_sftp_session_stats()` with `srtt_ms`, `rttvar_ms`, `rx_bps`, `tx_bps` per connection and in total (01 §10.4), used for read-ahead sizing (4.3) and `status --stats`. |
| R17 (MUST when advertised) | All `statvfs@openssh.com` fields as 64-bit. | **Met.** |
| R18 (MUST) | XP-compatible synchronization; no CRT-heavy dependencies; no callbacks under `sd_sftp` locks the vfs could re-enter. | **Met.** `*_sync` wrappers return `SD_E_WOULD_DEADLOCK` on an I/O thread; the vfs never calls them outside the host control thread (5.4). |
| R19 (MUST, new; D18) | Connection pool: 1–4 members per mount, secondary members only with non-interactive authentication, same host key and home as the primary, bulk-only channel on extra members (D19), per-member reconnect, writes failed by a secondary loss flagged so they can be resubmitted. | **Met** inside one `sd_sftp_session` (01 §10.9: `connections`, `SD_SFTP_O_STRIPED`, `EV_POOL`, `session_ready`, per-member stats); `sd_vfs` contract in 5.6. |

---

## 10. Backend selection and feature matrix

### 10.1 Selection

```
profile.backend = auto | dokany | webdav

auto:
  if profile needs Dokany-only features (folder mount, ACLs, files > 4 GiB-1 flagged)
       and Dokany available          -> dokany
  if scope = service and Dokany available -> dokany          (global drives: Dokany is primary, D11)
  if OS >= Win7 SP1 and native arch in {x86, x64, ARM64} and sd_dokan_probe() == OK -> dokany
  else if WebClient present and not disabled (or can be started) -> webdav
       (scope = service: system-wide mapping where the D11 spike passed for this OS,
        else per-user attach at logon, 7.7)
  else -> error with remediation:
       "Install Dokany (admin)" | "Enable WebClient / WebDAV Redirector feature (admin)"
dokany (forced): probe must be OK, else fail with the probe reason (no fallback)
webdav (forced): ensure_client must be OK, else fail (no fallback)
```

| Platform | Backends |
|---|---|
| XP SP3 x86, Server 2003 | WebDAV only (Server 2003: WebClient disabled by default) |
| Vista / Server 2008 | WebDAV only |
| 7 SP1 / 2008 R2 SP1 without SHA-2 updates | WebDAV only (Dokany driver fails Code 52) |
| 7 SP1+ x86/x64, 8.x, 10, 11 | Dokany (preferred) + WebDAV |
| 10/11 ARM64 | Dokany ≥ 2.2.0 ARM64 + WebDAV |
| ARM32 (Windows 10 on ARM / Windows 11 ≤ 23H2; RT 8.1 and IoT Core cannot run it, 04 §5.1) | WebDAV only, best effort (D5; only where WebClient exists) |
| Server 2012–2025 | Dokany; WebDAV only after adding Desktop Experience / WebDAV-Redirector |

### 10.2 Feature matrix

| Feature | Dokany | WebDAV |
|---|---|---|
| Max file size | unlimited (64-bit) | 4 GiB − 1 (default 50 MB unless the installer raised it) |
| Open latency of large file | 1–2 RTT (lazy, ranged reads) | full download before open |
| Partial write | ranged writes | full-file PUT on close |
| Write modes | `through` (default) / `behind` per profile | no observable difference: the PUT response is the acknowledgement point; the redirector itself uploads at close |
| Read-ahead, striping over the connection pool | yes (ours) | ours on the server side, but the redirector serializes whole files |
| Drive letter, per user | yes | yes |
| Folder mount (NTFS) | yes | no |
| Global drive (service) | yes, also before logon | per OS after the D11 spike: system-wide mapping (pre-logon only where G6 passed), else per-user attach after logon |
| Network drive type / Explorer "Disconnect" | yes (with network provider) | yes (per-user); not for a global link |
| Stable UNC for Network Shortcuts | `\\shelldrive\<share>` (with network provider) | no (port and token change); drive letter only |
| Security tab / ACL mapping | yes (synthesized) | no |
| Read-only attribute, hidden dot-files | yes | yes (via `Win32FileAttributes`) |
| Timestamps settable | mtime/atime | mtime/atime (PROPPATCH) |
| Share modes across local apps | kernel + vfs | redirector local + vfs per request |
| Office editing with locks | yes (local byte locks) | yes (DAV LOCK) |
| Change notifications to Explorer | yes (`DokanNotify*`) | no |
| Symlinks | follow/hide | follow/hide |
| Reparse points | postponed after 1.0 (D12) | no |
| Thumbnail suppression (`OFFLINE` hint) | not needed | option, default off (D22) |
| Free space | statvfs | statvfs via quota props |
| Read-only mount | yes | yes |
| Offline reads from cache | yes | yes (plus the redirector's own cache) |
| Needs admin once | Dokany install | only to fix limits / enable WebClient |
| OS | 7 SP1+ (x86/x64/ARM64) | XP SP3+ (all arch with WebClient) |

### 10.3 Target paths for "Add network location" (Network Shortcuts, D14)

Network Shortcuts are in v1 (M3; owner of the shell side: 03). A Network Shortcut is a folder in
`%AppData%\Microsoft\Windows\Network Shortcuts\` whose `target.lnk` points at a path, so the filesystem
layer only has to provide a target that stays valid across restarts:
- **Dokany with the network provider**: `\\shelldrive\<share>\[subpath]` (6.4). `<share>` is stable per
  profile. When the profile is not mounted, opening the shortcut fails like an unreachable SMB share;
  03's handler may offer to mount.
- **Dokany without the network provider, and folder mounts**: the drive letter or mount folder
  (`Z:\[subpath]`, `C:\mnt\host\[subpath]`).
- **WebDAV**: the drive letter only. The WebDAV UNC (`\\localhost@PORT\DavWWWRoot\s-<token>`) is never
  written into a shortcut: the port changes per start and the path token is a per-mount secret (7.3,
  7.4) that must not be persisted in a `.lnk` file.
- `sd_mount` exposes the chosen target per mount (`stable_target`) to the shell side; `sd_vfs` itself is
  unaffected.

---

## 11. Performance targets and measurement

**Reference setups**
- (L) LAN: 1 Gbit/s, RTT 0.3 ms, OpenSSH 9.x on Linux, NVMe.
- (W) WAN: 100 Mbit/s, RTT 50 ms (Linux `tc netem delay 25ms` on both directions).
- (W2) long fat WAN: 100 Mbit/s, RTT 200 ms (for the connection pool only).
- Client: 4-core x64, Windows 11. Spot checks on Win7 x86 and XP SP3 VMs, and on an ARM64 device.

Baseline = OpenSSH `sftp` (Windows build, same cipher, `-B 262144 -R 64`) for the same transfer.

**Assumptions** unless a row says otherwise: Dokany backend, `connections = 1` with two SFTP channels,
**`write_mode = through` (the default)**, application writes of 1 MiB (the bench default), memory cache
only. Rows marked *behind* assume `write_mode = behind`.

| Metric | Mode | Target |
|---|---|---|
| Sequential read 1 GiB, cold | any | ≥ 85% of baseline on L and W |
| Sequential read 1 GiB, cold, `connections = 4` | any | ≥ 1.5 × the `connections = 1` figure on W2, or ≥ 90% of link capacity |
| Sequential write 1 GiB, 1 MiB writes | through | ≥ 75% of baseline on L; ≥ 50% of baseline on W (one RTT per `WriteFile`: ≈ 1 MiB / (RTT + 1 MiB / bandwidth)) |
| Sequential write 1 GiB, 64 KiB writes | through | ≥ 90% of `64 KiB / (RTT + 64 KiB / bandwidth)` (RTT-bound; documented) |
| Sequential write 1 GiB, 1 MiB writes, `connections = 4` | through | ≥ 1.3 × the `connections = 1` figure on W (a call's chunks are striped) |
| Sequential write 1 GiB | behind | ≥ 75% of baseline on L and W, for any write size ≥ 4 KiB |
| Warm-cache read (memory tier) | any | ≥ 1 GB/s |
| Open existing file (attributes only), cold | any | ≤ 1 RTT + 1 ms |
| Open + first 4 KiB read, cold | any | ≤ 2 RTT + 2 ms (stat cached: OPEN + READ) |
| `dir` of 10,000 entries, cold | any | ≤ ceil(n / entries per READDIR) × RTT + 300 ms; ≤ 1 s on L |
| Same, warm | any | ≤ 100 ms |
| Create 1,000 × 4 KiB files (xcopy) | through | ≤ 4 RTT per file on W (create, write, close + setstat); ≤ 4 s on L |
| Create 1,000 × 4 KiB files (xcopy) | behind | ≤ 3 RTT per file on W (write pipelined with close); ≤ 3 s on L |
| Explorer opens a 1,000-entry folder, cold | any | ≤ 400 ms on L |
| CPU at 100 MB/s sequential read (x64) | any | ≤ 1 core total (vfs share ≤ 15%) |
| Memory per mount (excluding cache budget) | through | ≤ 20 MB with `connections = 1`, + 4 MB per extra connection |
| Memory per mount (excluding cache budget) | behind | as above + the write window actually used (≤ 64 MiB per mount) |
| Reconnect to I/O resumption | any | ≤ backoff + 2 RTT after the TCP connect (per connection) |
| Dead-link detection during I/O | any | the operation returns `TIMEOUT`/`DISCONNECTED` within 25 s; never a Dokany timeout (5.7) |
| WebDAV: GET 10 MB (redirector open) | any | ≤ 1.5 × Dokany sequential read time + 100 ms on L |
| WebDAV: PROPFIND depth 1 of 1,000 entries | any | ≤ 150 ms on L (server side ≤ 30 ms with warm cache); service server with per-request auth (7.7): ≤ 300 ms |

**Measurement**
- `shelldrive diag bench <drive> [--scenario ...] [--write-mode through|behind]` (C7; developer and
  support command): a built-in harness using plain Win32 file APIs (CreateFile, ReadFile/WriteFile with
  1 MiB and 64 KiB buffers, with and without `FILE_FLAG_NO_BUFFERING`, FindFirstFileEx, MoveFileEx,
  DeleteFile). It runs on both backends, reports the mount's write mode and pool size, and emits JSON
  (English keys).
- `shelldrive status --stats <drive>` (C7): dumps `sd_vfs_stats` (round trips per op type, cache hit
  ratio, in-flight peaks, bytes, reconnects, per pool member). Used to check the per-operation RTT budgets
  above exactly, independent of noise.
- Real-world scripts: robocopy of a source tree (many small files), 7-Zip extraction onto the drive,
  Explorer folder open timed via UI Automation, Office open/save of a 20 MB .docx, each in both write
  modes.
- CI: x64 Windows runner + WSL sshd (D21: test infrastructure only) on loopback for regression runs
  (± 10% alarm); WAN figures run on a nightly job with netem on the self-hosted lab. Dokany is installed
  on the CI runner (runners are admin VMs). XP/Win7/ARM64 runs are manual before release (M6).

---

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| WebClient is deprecated (Nov 2023) and may be removed in a future Windows release | WebDAV backend disappears on new Windows | Dokany is the primary backend on 7+; WebDAV is the fallback and the XP/Vista/ARM32 path. Track the deprecation page each release. |
| NTLM deprecation / policies blocking NTLM | WebDAV loopback auth fails | Negotiate (future local Kerberos/IAKerb), self-test, token-only fallback for per-user mounts with a warning; global WebDAV refuses token-only |
| Redirector whole-file caching and 4 GiB cap | poor UX on big files over WebDAV | prefer Dokany; installer raises the limits; clear UI errors (0x800700DF explained) |
| Win7 Dokany signing (SHA-2) not loading on unpatched systems | Dokany unavailable | 04's detection; fall back to WebDAV; doc |
| `dokan2.dll` needs the VC++ runtime | Dokany unloadable after an MSI-only install | C31 lab check; `DokanSetup.exe` bundle in offline EXEs; probe reports the loader error (6.1) |
| Another product installed Dokany 2.0.x | Dokany unavailable | detect, explain, 04's decision table; never auto-replace |
| Write-through throughput on high-RTT links | slow copies with small application writes | documented targets (11); `write_mode = behind` opt-in; striping of large writes over the pool |
| Write-behind error after the app closed the file (Dokany `Cleanup` is void) | data loss the app does not see | opt-in only; bounded window, sticky errors, synchronous drain at cleanup, always-on `write_failed` notification, grace retransmit |
| Dokany kernel cache delays writes (verify, 4.4) | write-through guarantee holds only at flush/close | documented in A5; Windows reports "Delayed Write Failed" |
| Pool members reach different servers (DNS round robin, load balancer) | incoherent data | host key and home equality check per member (5.6) |
| Server limits on sessions/connections (`MaxStartups`, `MaxSessions`) | extra connections refused | pool shrinks silently to what the server allows; default 1 |
| Global WebDAV mapping behaves differently per OS or shares connections across users | users see each other's access or no drive | lab go/no-go G1–G6 per OS, per-request auth fallback, per-user attach fallback (7.7) |
| 1-second mtime + same size hides remote rewrite | stale cached reads | hot-block rule, TTL, close-to-open revalidation, refresh command |
| Case collisions on case-sensitive servers | confusing names | deterministic `~cN` mangling, logged |
| Dokany kernel request timeout during long ops | app sees errors | 25 s vfs deadline, liveness probe (C16), `DokanResetTimeout` on progress, bounded windows |
| Unknown uid at mount (no exec, home owned by another account) | wrong read-only attributes until the first create | "any `w` bit" rule errs toward writable (3.1, 3.4); `identity_probe = exec` opt-in |
| AV/indexer reading whole remote files | bandwidth storms | network drive type, `allow_system` toggle, docs |
| XP port handling / UNC syntax unverified | XP WebDAV mount fails | http-URL mapping form, port-80 fallback, early test on XP SP3 |

---

## 13. Open questions (lab items on the test matrix)

Product decisions are closed (decisions.md). What remains are platform facts to verify:

1. Does the Dokany 2.x kernel enforce share access itself (making the vfs check redundant there)?
2. Does a folder mount work with `CURRENT_SESSION` (per-user folder mounts), or only globally?
3. XP SP3: confirm non-80 port mapping, the accepted remote-name syntax, the WebClient default start type,
   `FileSizeLimitInBytes` applicability and LOCK behavior.
4. The redirector's local cache location and protection (TfsStore under LocalService?). It affects the
   privacy statement.
5. Does Windows Firewall on XP SP3 prompt for loopback-only listeners?
6. Does Dokany 2.3.1 route cached application writes through the Cache Manager (4.4)? The answer goes
   into the wording of amendment A5's documentation.
7. D11 spike (7.7): G1–G6 per OS and mechanism, including whether WebClient ever reuses an
   authenticated TCP connection across logon sessions.
8. D23 compatibility list: Office, Visual Studio, Git for Windows and backup tools against `NTFS` and a
   custom `volume_fs_name`, to document which apps need `NTFS`.
9. Dokany's default request timeout value in 2.3.1 (15 s per the header) and the status `mklink` reports
   on a Dokany volume.

---

## Changelog: integrated decisions

Applied in this revision (2026-10-24):

- **decisions.md**: D1 (own `dokan_abi.h`, no copied header), D5 (ARM32 WebDAV best effort), D9 (write
  mode per profile, default write-through; write-behind opt-in with mitigations; error, flush/close
  semantics; performance targets state their mode), D10 (uid/gid discovery without exec, optional
  `identity_probe = exec`), D11 (global WebDAV attempt: service-hosted server, mechanisms A/B, lab
  go/no-go G1–G6 per OS, per-user attach fallback, SSPI access control with the service as server), D12
  (symlinks `follow|hide`, reparse postponed, `reparse` reserved), D13 (amendments A1–A5, A7 as adjusted),
  D14 (Network Shortcut target forms), D18 (connection pool 1–4: metadata on primary, bulk striping,
  per-connection reconnect and handle re-open), D19 (two channels per connection, auto-degrade), D21
  (WSL sshd for CI only), D22 (`OFFLINE` hint option, default off), D23 (`NTFS` default, configurable), D32
  (Dokany packaging per dependency check).
- **Review conflicts**: C7 (CLI names `diag --fix webclient`, `diag bench`, `status --stats`,
  `refresh`), C11 (agent logon start), C12 (cache paths from the host), C13 (01 names canonical, `sd_err`
  table), C14 (no vfs-side refinement probes), C15 (vfs owns chunking), C16 (25 s / 50 s deadlines,
  liveness probe), C17 (meta/bulk request classes), C18 (identity), C23 (two-stage name mapping), C24
  (02 tables normative), C26 (no Basic; elevated attach via same SID), C27 (as replaced by D11), C28
  (`WEBDAV_TUNING` scope and restore), C29 (`symlinks` values), C30 (`/s-<token>/` kept, labels via
  `_LabelFromReg`), C31 (VC++ dependency lab check), C32 (04 normative for SHA-2 detection and upgrade
  table), C33 (`Unmounted` posts to the control thread), C38 (own Dokany ABI header), C45 (localized
  offline suffix from the host, `write_failed` event), C46 (global memory budget, per-profile disk cache
  default 0, schema owned by 03).
- **Review items**: R1–R18 resolutions recorded in section 9, plus new R19 (pool); threading rules
  00 §4.1 (1–7) applied in 5.4/5.5/5.7; FAILED-mount behaviour (00 §4) in 5.1; requirement amendments
  A1, A2, A3, A4 (as rewritten by D11), A5 (as rewritten by D9), A7.
- Local decision ids renamed `FS-1`…`FS-17` to avoid clashing with `decisions.md` ids. Resolved open
  questions removed: reparse points (D12), `OFFLINE` hint (D22), volume FS name (D23, now a lab list),
  R5/R14 style (review), uid/gid via exec (D10), global WebDAV (D11, now a lab spike).
- Final reconciliation 2026-10-24: the pool follows 01 §10.9 — one `sd_sftp_session` per mount
  (`sd_vfs_mount` takes a single session; `sd_vfs_pool_add/remove` and `sd_vfs_set_identity` removed),
  extra connections open a bulk channel only (D19), striping and sub-handles live in `sd_sftp`
  (`SD_SFTP_O_STRIPED`; the vfs only decides when to set it), secondary loss → resubmit writes flagged
  `session_ready = 1`, primary loss closes all members (5.6, 1.4, 2.1, 4.3, 4.4, 5.1, 5.3, 6.6); the
  `exec` identity probe runs inside `sd_sftp` and arrives in `server_info.identity` (3.4); R-table in 9
  updated to "met" where 01 now delivers (R1, R3, R10, R12, R13, R16, R19); global-mount access uses 03's
  `service_access` key (default `BUILTIN\Users`) instead of "allowed group, default Authenticated Users"
  (6.4, 6.7, 7.7); 7.7 names the 03 setting values `system` / `link` / `attach`.
