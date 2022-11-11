#define HAVE_CASPER 1

#include <err.h>
#include <errno.h>
#include <ifaddrs.h>
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


typedef struct cap_result {
  int *sockets;
  cap_channel_t *capifname;
} cap_result_t;


static int mib[] = {
  CTL_NET,
  PF_ROUTE,
  0,             /* protocol */
  0,             /* wildcard address family */
  NET_RT_IFLISTL,/* extra fields for extensible msghdr structs */
  0              /* no flags */
};
static u_int miblen = sizeof(mib) / sizeof(mib[0]);
static const u_char masktolen[256] = {
  [0xff] = 8 + 1,
  [0xfe] = 7 + 1,
  [0xfc] = 6 + 1,
  [0xf8] = 5 + 1,
  [0xf0] = 4 + 1,
  [0xe0] = 3 + 1,
  [0xc0] = 2 + 1,
  [0x80] = 1 + 1,
  [0x00] = 0 + 1,
};
static cap_result_t *cap;

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


static bool
default_v4(struct sockaddr *addr) {
  struct sockaddr_in *destination = (struct sockaddr_in *)((char *)addr + SA_SIZE(addr) * RTAX_DST);
  struct sockaddr_in *mask = (struct sockaddr_in *)((char *)addr + SA_SIZE(addr) * RTAX_NETMASK);
  if(destination->sin_addr.s_addr == INADDR_ANY && mask->sin_addr.s_addr == 0) {
    return true;
  }
  return false;
}


static bool
default_v6(struct sockaddr *addr) {
  u_char *p, *lim;
  u_char masklen;
  int i;
  bool illegal = false;
  struct sockaddr_in6 *destination = (struct sockaddr_in6 *)((char *)addr + SA_SIZE(addr) * RTAX_DST);
  struct sockaddr_in6 *mask = (struct sockaddr_in6 *)((char *)addr + SA_SIZE(addr) * RTAX_NETMASK);

  if (mask) {
    p = (u_char *)&mask->sin6_addr;
    for (masklen = 0, lim = p + 16; p < lim; p++) {
      if (masktolen[*p] > 0) {
        /* -1 is required. */
        masklen += (masktolen[*p] - 1);
      } else
        illegal = true;
    }
  } else {
    masklen = 128;
  }

  if (masklen == 0 && IN6_IS_ADDR_UNSPECIFIED(&destination->sin6_addr)) {
    return true;
  }
  return false;
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
set_egress(const char *name, int inet, int fib) {
  int s = cap->sockets[fib];
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
unset_egress(const char *name, int inet, int fib) {
  int s = cap->sockets[fib];
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


static void
tag(struct sockaddr *data, char *name, int fib) {
  switch(data->sa_family) {
    case AF_INET: {
      if (default_v4(data)) {
        int rc = set_egress(name, 4, fib);
        if (rc < 0) {
          perror("set_egress");
        }
      }
      break;
    }
    case AF_INET6: {
      if (default_v6(data)) {
        int rc = set_egress(name, 6, fib);
        if (rc < 0) {
          perror("set_egress");
        }
      }
      break;
    }
  }
}


static void
untag(struct sockaddr *data, char *name, int fib) {
  switch(data->sa_family) {
    case AF_INET: {
      if (default_v4(data)) {
        int rc = unset_egress(name, 4, fib);
        if (rc < 0) {
          perror("unset_egress");
        }
      }
      break;
    }
    case AF_INET6: {
      if (default_v6(data)) {
        int rc = unset_egress(name, 6, fib);
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
  size_t needed;
  char *buf;
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
    if (rtm->rtm_version != RTM_VERSION) {
      continue;
    }
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


static struct msghdr *
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


static void
sock_init(int fibs, struct kevent *events) {
  int rc;
  void *limit;
  cap_channel_t *capcas;
  unsigned long *commands = malloc(sizeof(unsigned long) * 2);
  cap_rights_t *r = malloc(sizeof(cap_rights_t));

  commands[0] = SIOCAIFGROUP;
  commands[1] = SIOCDIFGROUP;

  cap_rights_init(r, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SOCK_CLIENT, CAP_IOCTL);
  for (int i = 0; i < fibs; ++i) {
    EV_SET(events+i, cap->sockets[i], EVFILT_READ, EV_ADD | EV_CLEAR, NOTE_READ, 0, NULL);
    if (cap_rights_limit(cap->sockets[i], r) < 0) {
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
  cap->capifname = cap_service_open(capcas, "system.sysctl");
  if (cap->capifname == NULL) {
    perror("cap_service_open");
    exit(1);
  }
  cap_close(capcas);

  limit = cap_sysctl_limit_init(cap->capifname);
  cap_sysctl_limit_mib(limit, mib, miblen, CAP_SYSCTL_READ);
  if (cap_sysctl_limit(limit) < 0) {
    perror("cap_sysctl_limit");
    exit(1);
  }
  for (int i = 0; i < fibs; ++i) {
    if (cap_ioctls_limit(cap->sockets[i], commands, 2) < 0) {
      perror("cap_ioctl_limit");
      exit(1);
    }
  }

  free(commands);
  free(r);
}


static void
setup(int fib) {
  size_t needed;
  char *buf;
  char *next;
  char *lim;
  struct rt_msghdr *rtm;
  struct sockaddr *sa;
  struct if_msghdrl *ifm;
  struct sockaddr_dl *dl;
  struct ifaddrs *ifa;
  struct ifaddrs *ifap;
  bool ipv4default = false;
  bool ipv6default = false;
  int ifindex;
  int mib[] = {
    CTL_NET,
    PF_ROUTE,
    0,
    0,
    NET_RT_DUMP,
    0,
    fib
  };
  u_int miblen = sizeof(mib) / sizeof(mib[0]);

  if (sysctl(mib, miblen, NULL, &needed, NULL, 0) < 0) {
    err(1, "getting size for routing table on %d", fib);
  }
  if ((buf = malloc(needed)) == NULL) {
    errx(2, "malloc(%lu)", (unsigned long)needed);
  }
  if (sysctl(mib, nitems(mib), buf, &needed, NULL, 0) < 0) {
    err(1, "getting routing table on %d", fib);
  }
  lim = buf + needed;

  if (getifaddrs(&ifap) != 0) {
    err(1, "getifaddrs");
  }
  for (next = buf; next < lim; next += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)next;
    if (rtm->rtm_version != RTM_VERSION) {
      continue;
    }
    sa = (struct sockaddr *)(rtm + 1);
    if (sa->sa_family == AF_INET) {
      ipv4default = default_v4(sa);
    } 
    if (sa->sa_family == AF_INET6) {
      ipv6default = default_v6(sa);
    }
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      dl = (struct sockaddr_dl *)ifa->ifa_addr;
      ifindex = dl->sdl_index;
      if (rtm->rtm_index == ifindex) {
        if (ipv4default) {
          set_egress(ifa->ifa_name, 4, fib);
        }
        if (ipv6default) {
          set_egress(ifa->ifa_name, 6, fib);
        }
      }
    }
  }

  free(buf);
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
  struct msghdr *msg;
  struct rt_msghdr *hd;
  struct kevent *events;
  struct kevent tevent;
  struct ifaddrs *ifa;
  struct ifaddrs *ifap;

  ver = version();
  printf("egress-monitor(%s): starting\n", ver);

  fibs = getfibs();
  if (fibs < 0) {
    perror("get fibs");
    exit(1);
  }

  cap = malloc(sizeof(cap_result_t));
  cap->sockets = malloc(sizeof(int) * fibs);
  for (fib = 0; fib < fibs; ++fib) {
    setfib(fib);
    cap->sockets[fib] = socket(PF_ROUTE, SOCK_RAW, 0);
  }
  if (getifaddrs(&ifap) != 0) {
    err(1, "getifaddrs");
  }
  for (fib = 0; fib < fibs; ++fib) {
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      unset_egress(ifa->ifa_name, 4, fib);
      unset_egress(ifa->ifa_name, 6, fib);
    }
    setup(fib);
  }

  kq = kqueue();
  if (kq == -1) {
    perror("kqueue");
    exit(1);
  }

  events = malloc(sizeof(struct kevent) * fibs);

  msg = init_msg();
  hd = msg->msg_iov[0].iov_base;
  sock_init(fibs, events);
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
          tag(data, name, fib);
          break;
        }
        case RTM_DELETE: {
          untag(data, name, fib);
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
  printf("egress-monitor(%s): stopped\n", ver);
  free(ver);

  return 0;
}
