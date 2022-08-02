#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include "config.h"


const char *
inet_ntop(int af, const void *src, char *dst, socklen_t size);


static char *
version() {
  char *ver = malloc(16 * sizeof(char));
  snprintf(ver, 16, "%d.%d.%d", major, minor, patch);
  return ver;
}


static int
getfibs() {
  int value, rc;
  size_t valsize = sizeof(value);
  rc = sysctlbyname("net.fibs", &value, &valsize, NULL, 0);
  if (rc < 0) {
    return rc;
  }
  return value;
}


static int
default_v4(struct sockaddr_in *addr) {
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
  const char *default_ip = "0.0.0.0";
  int len = strlen(default_ip);
  if (strncmp(ip, default_ip, len) == 0) {
    return 1;
  }
  return 0;
}


static int
default_v6(struct sockaddr_in6 *addr) {
  char ip[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(addr->sin6_addr), ip, INET6_ADDRSTRLEN);
  const char *default_ip = "::";
  int len = strlen(default_ip);
  if (strncmp(ip, default_ip, len) == 0) {
    return 1;
  }
  return 0;
}


static char *
egress_name(const char *name, int inet, int fib) {
  if (inet != 4 && inet != 6) {
    return NULL;
  }
  char *groupname = malloc(IFNAMSIZ * sizeof(char));
  snprintf(groupname, IFNAMSIZ, "v%dfib%d%s", inet, fib, IFG_EGRESS);
  return groupname;
}


static int
set_egress(const char *name, int inet, int s, int fib) {
  struct ifgroupreq ifgr;
  char *egress = egress_name(name, inet, fib);
  if (!egress) {
    return -1;
  }
  int namelen = strlen(name) + 1;
  int egresslen = strlen(egress) + 1;
  strlcpy(ifgr.ifgr_name, name, namelen);
  strlcpy(ifgr.ifgr_group, egress, egresslen);
  printf("set: %s %s\n", ifgr.ifgr_name, ifgr.ifgr_group);
  free(egress);
  if (ioctl(s, SIOCAIFGROUP, (caddr_t)&ifgr) == -1 && errno != EEXIST) {
    return -1;
  }
  return 0;
}


static int
unset_egress(const char *name, int inet, int s, int fib) {
  struct ifgroupreq ifgr;
  char *egress = egress_name(name, inet, fib);
  int namelen = strlen(name) + 1;
  int egresslen = strlen(egress) + 1;
  strlcpy(ifgr.ifgr_name, name, namelen);
  strlcpy(ifgr.ifgr_group, egress, egresslen);
  printf("unset: %s %s\n", ifgr.ifgr_name, ifgr.ifgr_group);
  free(egress);
	if (ioctl(s, SIOCDIFGROUP, (caddr_t)&ifgr) == -1 && errno != ENOENT) {
    return -1;
  }
  return 0;
}


void
tag(struct sockaddr *data, char *name, int s, int fib) {
  switch(data->sa_family) {
    case AF_INET: {
      if (default_v4((struct sockaddr_in *)data)) {
        int rc = set_egress(name, 4, s, fib);
        if (rc < 0) {
          perror("set_egress");
        }
      }
      break;
    }
    case AF_INET6: {
      if (default_v6((struct sockaddr_in6 *)data)) {
        int rc = set_egress(name, 6, s, fib);
        if (rc < 0) {
          perror("set_egress");
        }
      }
      break;
    }
  }
}


void
untag(struct sockaddr *data, char *name, int s, int fib) {
  switch(data->sa_family) {
    case AF_INET: {
      if (default_v4((struct sockaddr_in *)data)) {
        int rc = unset_egress(name, 4, s, fib);
        if (rc < 0) {
          perror("unset_egress");
        }
      }
      break;
    }
    case AF_INET6: {
      if (default_v6((struct sockaddr_in6 *)data)) {
        int rc = unset_egress(name, 6, s, fib);
        if (rc < 0) {
          perror("unset_egress");
        }
      }
      break;
    }
  }
}


int
main() {
  const char *ver = version();
  printf("egress-monitor(%s): starting\n", ver);
  int rc, s, n, fib, fibs = getfibs(), kq = kqueue();
  if (fibs < 0) {
    perror("get fibs");
    exit(1);
  }
  if (kq == -1) {
    perror("kqueue");
    exit(1);
  }
  int sockets[fibs];
  char rest[1024];
  struct rt_msghdr hd;
  struct msghdr msg;
  struct iovec iov[2];
  struct kevent events[fibs];
  struct kevent tevent;
  cap_rights_t r;

  memset(&hd, 0, sizeof(hd));
  memset(&msg, 0, sizeof(msg));
  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = &hd;
  iov[0].iov_len = sizeof(hd);
  iov[1].iov_base = &rest;
  iov[1].iov_len = sizeof(rest);
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;

  cap_rights_init(&r, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SOCK_CLIENT);

  for (int i = 0; i < fibs; ++i) {
    setfib(i);
    s = socket(PF_ROUTE, SOCK_RAW, 0);
    sockets[i] = s;
    EV_SET(events+i, s, EVFILT_READ, EV_ADD | EV_CLEAR, NOTE_READ, 0, NULL);
    // if (cap_rights_limit(s, &r) < 0) {
    //   perror("cap_rights_limit");
    //   exit(1);
    // }
  }
  // if (cap_enter() < 0) {
  //   perror("cap_enter");
  //   exit(1);
  // }
  rc = kevent(kq, events, fibs, NULL, 0, NULL);
  if (rc < 0) {
    perror("kevent");
    exit(1);
  }

  printf("egress-monitor(%s): started\n", ver);
  for (;;) {
    rc = kevent(kq, NULL, 0, &tevent, 1, NULL);
    if (rc == -1 || tevent.data == 0) {
      perror("kevent");
      break;
    }
    for (fib = 0; fib < fibs; ++fib) {
      if (sockets[fib] == tevent.ident) break;
    }
    if (fib == fibs) {
      fprintf(stderr, "Can not find the FIB that emited the event!\n");
      break;
    }
    n = recvmsg(tevent.ident, &msg, 0);
    if (n < 0) {
      perror("recvmsg failed");
      break;
    }
    if (hd.rtm_index) {
      char *ret;
      char name[IFNAMSIZ];
      ret = if_indextoname(hd.rtm_index, name);
      if (!ret) {
        perror("if_indextoname");
        break;
      }
      struct sockaddr *data = iov[1].iov_base;
      switch(hd.rtm_type) {
        case RTM_ADD: {
          tag(data, name, s, fib);
          break;
        }
        case RTM_DELETE: {
          untag(data, name, s, fib);
          break;
        }
      }
    }
  }
  printf("egress-monitor(%s): stopped\n", ver);
  return 0;
}
