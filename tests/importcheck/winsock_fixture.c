/* Test fixture for sd-importcheck: imports the WinSock 1.1 functions that the SDK 7.1A ws2_32.lib binds
 * by ordinal (closesocket #3, connect #4, recv #16, send #19, setsockopt #21, WSAGetLastError #111,
 * WSAStartup #115), so the audit must map them to names and accept them on the XP floor list. Never
 * shipped and never run. */
#include <winsock2.h>

#include <string.h>

int main(int argc, char **argv)
{
  WSADATA wd;
  SOCKET s = (SOCKET)argc;
  struct sockaddr sa;
  char b[1] = { 0 };
  int v = 0, r = 0;
  (void)argv;
  memset(&sa, 0, sizeof(sa));
  if (argc > 100) {
    r |= WSAStartup(MAKEWORD(2, 2), &wd);
    r |= connect(s, &sa, (int)sizeof(sa));
    r |= setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&v, (int)sizeof(v));
    r |= send(s, b, 1, 0);
    r |= recv(s, b, 1, 0);
    r |= closesocket(s);
    r |= WSAGetLastError();
  }
  return r;
}
