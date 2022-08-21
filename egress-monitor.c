#define HAVE_CASPER 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <libcasper.h>
#include <casper/cap_sysctl.h>

#include "config.h"


static int mib[] = {
  CTL_NET,
  PF_ROUTE,
  0,             /* protocol */
  0,             /* wildcard address family */
  NET_RT_IFLISTL,/* extra fields for extensible msghdr structs */
  0              /* no flags */
};
static u_int miblen = sizeof(mib) / sizeof(mib[0]);


typedef struct cap_result {
  int *sockets;
  cap_channel_t *capifname;
} cap_result_t;


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


static char *
ifname(cap_channel_t *capifname, int index) {
  size_t needed = 4096;
  char *buf = malloc(needed);
  char *next;
  struct rt_msghdr *rtm;
  struct if_msghdrl *ifm;

  if (cap_sysctl(capifname, mib, miblen, NULL, &needed, NULL, 0) < 0) {
    perror("cap_sysctl reading needed");
    return NULL;
  }
  if ((buf = malloc(needed)) == NULL) {
    return NULL;
  }
  if (cap_sysctl(capifname, mib, miblen, buf, &needed, NULL, 0) < 0) {
    perror("cap_sysctl reading mib");
    free(buf);
    return NULL;
  }

  for (next = buf; next < buf + needed; next += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)next;
    if (rtm->rtm_version != RTM_VERSION)
      continue;
    switch (rtm->rtm_type) {
      case RTM_IFINFO: {
        ifm = (struct if_msghdrl *)rtm;
        if (ifm->ifm_addrs & RTA_IFP && ifm->ifm_index == index) {
          struct sockaddr_dl *dl = (struct sockaddr_dl *)IF_MSGHDRL_RTA(ifm);
          int len = dl->sdl_nlen + 1;
          char *name = malloc(len + 1);
          strlcpy(name, dl->sdl_data, len);
          free(buf);
          return name;
        }
        break;
      }
    }
  }
  free(buf);

  return NULL;
}


struct msghdr *
init_msg() {
  size_t msgsize = sizeof(struct msghdr);
  size_t hdsize = sizeof(struct rt_msghdr);
  size_t iovsize = sizeof(struct iovec) * 2;
  size_t restsize = 1024;

  struct msghdr *msg = malloc(msgsize);
  struct rt_msghdr *hd = malloc(hdsize);
  struct iovec *iov = malloc(iovsize);
  char *rest = malloc(restsize);

  memset(msg, 0, msgsize);
  memset(hd, 0, hdsize);
  memset(iov, 0, iovsize);

  iov[0].iov_base = hd;
  iov[0].iov_len = hdsize;
  iov[1].iov_base = rest;
  iov[1].iov_len = restsize;
  msg->msg_iov = iov;
  msg->msg_iovlen = 2;

  return msg;
}


cap_result_t *
sock_init(int fibs, struct kevent *events) {
  int rc;
  void *limit;
  cap_channel_t *capcas;
  unsigned long *commands = malloc(sizeof(unsigned long) * 2);
  cap_rights_t *r = malloc(sizeof(cap_rights_t));
  cap_result_t *result = malloc(sizeof(cap_result_t));
  result->sockets = malloc(sizeof(int) * fibs);

  commands[0] = SIOCAIFGROUP;
  commands[1] = SIOCDIFGROUP;

  cap_rights_init(r, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SOCK_CLIENT, CAP_IOCTL);
  for (int i = 0; i < fibs; ++i) {
    setfib(i);
    result->sockets[i] = socket(PF_ROUTE, SOCK_RAW, 0);
    EV_SET(events+i, result->sockets[i], EVFILT_READ, EV_ADD | EV_CLEAR, NOTE_READ, 0, NULL);
    if (cap_rights_limit(result->sockets[i], r) < 0) {
      perror("cap_rights_limit");
      exit(1);
    }
  }

  capcas = cap_init();
  if (capcas == NULL) {
    perror("cap_init");
    exit(1);
  }

  rc = chroot("/var/empty");
  if (rc < 0) {
    perror("chroot");
    exit(1);
  }

  if (cap_enter() < 0) {
    perror("cap_enter");
    exit(1);
  }
  result->capifname = cap_service_open(capcas, "system.sysctl");
  if (result->capifname == NULL) {
    perror("cap_service_open");
    exit(1);
  }
  cap_close(capcas);

  limit = cap_sysctl_limit_init(result->capifname);
  cap_sysctl_limit_mib(limit, mib, miblen, CAP_SYSCTL_READ);
  if (cap_sysctl_limit(limit) < 0) {
    perror("cap_sysctl_limit");
    exit(1);
  }
  for (int i = 0; i < fibs; ++i) {
    if (cap_ioctls_limit(result->sockets[i], commands, 2) < 0) {
      perror("cap_ioctl_limit");
      exit(1);
    }
  }

  free(commands);
  free(r);
  return result;
}


int
main() {
  char *ver;
  int rc;
  int s;
  int n;
  int fib;
  int fibs;
  int kq;
  cap_result_t *cap;
  struct msghdr *msg;
  struct rt_msghdr *hd;
  struct kevent *events;
  struct kevent tevent;

  ver = version();
  printf("egress-monitor(%s): starting\n", ver);

  fibs = getfibs();
  if (fibs < 0) {
    perror("get fibs");
    exit(1);
  }

  kq = kqueue();
  if (kq == -1) {
    perror("kqueue");
    exit(1);
  }

  events = malloc(sizeof(struct kevent) * fibs);

  msg = init_msg();
  hd = msg->msg_iov[0].iov_base;
  cap = sock_init(fibs, events);
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
      if (cap->sockets[fib] == tevent.ident) {
        s = tevent.ident;
        break;
      }
    }
    if (fib == fibs) {
      fprintf(stderr, "Can not find the FIB that emited the event!\n");
      continue;
    }
    n = recvmsg(tevent.ident, msg, 0);
    if (n < 0) {
      perror("recvmsg failed");
      continue;
    }
    if (hd->rtm_index) {
      char *name = ifname(cap->capifname, hd->rtm_index);
      if (!name) {
        continue;
      }
      struct sockaddr *data = msg->msg_iov[1].iov_base;
      switch(hd->rtm_type) {
        case RTM_ADD: {
          tag(data, name, s, fib);
          break;
        }
        case RTM_DELETE: {
          untag(data, name, s, fib);
          break;
        }
      }
      free(name);
    }
  }
  free(cap->sockets);
  free(cap->capifname);
  free(cap);
  free(msg->msg_iov[0].iov_base);
  free(msg->msg_iov[1].iov_base);
  free(msg->msg_iov);
  free(msg);
  free(events);
  free(ver);
  printf("egress-monitor(%s): stopped\n", ver);

  return 0;
}
