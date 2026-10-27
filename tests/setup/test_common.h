/* Helpers shared by the setup tests. */
#ifndef SD_SETUP_TEST_COMMON_H
#define SD_SETUP_TEST_COMMON_H

#include <windows.h>
#include <strsafe.h>
#include <stddef.h>

#define SD_SETUP_COUNTOF_LOCAL(a) (sizeof(a) / sizeof((a)[0]))

/* Folder with the CAB fixtures, generated at build time (CMakeLists.txt in this directory). */
#ifndef SD_SETUP_TEST_DATA
#define SD_SETUP_TEST_DATA "."
#endif

/* Reads a whole file into a heap buffer (free with HeapFree on the process heap). 0 on success. */
int test_read_file(const wchar_t *path, unsigned char **buf, size_t *size);

/* Creates %TEMP%\sdtest-<hex>; returns 0 on success. */
int test_make_temp_dir(wchar_t *out, size_t cch);

/* Recursively removes a folder created by the tests. */
void test_remove_tree(const wchar_t *dir);

/* ASCII to wide for the fixture path (the CMake definition is ASCII). */
void test_fixture_path(const wchar_t *leaf, wchar_t *out, size_t cch);

#endif /* SD_SETUP_TEST_COMMON_H */
