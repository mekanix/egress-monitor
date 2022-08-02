#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>


const char *
inet_ntop(int af, const void *src, char *dst, socklen_t size);


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
egress_name(const char *name, int inet) {
  char version = inet == 4 ? '4' : '6';
  char *groupname = malloc(IFNAMSIZ * sizeof(char));
  int egresslen = strlen(IFG_EGRESS) + 1;
  groupname[0] = 'v';
  groupname[1] = version;
  strlcpy(groupname+2, IFG_EGRESS, egresslen);
  return groupname;
}


static int
set_egress(const char *name, int inet, int s) {
  struct ifgroupreq ifgr;
  char *egress = egress_name(name, inet);
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
unset_egress(const char *name, int inet, int s) {
  struct ifgroupreq ifgr;
  char *egress = egress_name(name, inet);
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


int
main() {
  int rc, s, n, fibs = getfibs(), kq = kqueue();
  if (fibs < 0) {
    perror("get fibs");
    exit(1);
  }
  if (kq == -1) {
    perror("kqueue");
    exit(1);
  }
  char rest[1024];
  struct rt_msghdr hd;
  struct msghdr msg;
  struct iovec iov[2];
  struct kevent event;
  struct kevent tevent;


  memset(&hd, 0, sizeof(hd));
  memset(&msg, 0, sizeof(msg));
  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = &hd;
  iov[0].iov_len = sizeof(hd);
  iov[1].iov_base = &rest;
  iov[1].iov_len = sizeof(rest);
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;

  s = socket(PF_ROUTE, SOCK_RAW, 0);
  EV_SET(&event, s, EVFILT_READ, EV_ADD | EV_CLEAR, NOTE_READ, 0, NULL);
  rc = kevent(kq, &event, 1, NULL, 0, NULL);
  if (rc < 0) {
    perror("kevent");
    exit(1);
  }

  for (;;) {
    rc = kevent(kq, NULL, 0, &tevent, 1, NULL);
    if (rc == -1 || tevent.data == 0) {
      perror("kevent");
      break;
    }
    n = recvmsg(s, &msg, 0);
    if (n < 0) {
      perror("recvmsg failed");
      break;
    }
    if (hd.rtm_index) {
      char name[IFNAMSIZ];
      if_indextoname(hd.rtm_index, name);
      struct sockaddr *data = iov[1].iov_base;
      switch(hd.rtm_type) {
        case RTM_ADD: {
          switch(data->sa_family) {
            case AF_INET: {
              if (default_v4((struct sockaddr_in *)data)) {
                int rc = set_egress(name, 4, s);
                if (rc < 0) {
                  perror("set_egress");
                }
              }
              break;
            }
            case AF_INET6: {
              if (default_v6((struct sockaddr_in6 *)data)) {
                int rc = set_egress(name, 6, s);
                if (rc < 0) {
                  perror("set_egress");
                }
              }
              break;
            }
          }
          break;
        }
        case RTM_DELETE: {
          switch(data->sa_family) {
            case AF_INET: {
              if (default_v4((struct sockaddr_in *)data)) {
                int rc = unset_egress(name, 4, s);
                if (rc < 0) {
                  perror("unset_egress");
                }
              }
              break;
            }
            case AF_INET6: {
              if (default_v6((struct sockaddr_in6 *)data)) {
                int rc = unset_egress(name, 6, s);
                if (rc < 0) {
                  perror("unset_egress");
                }
              }
              break;
            }
          }
          break;
        }
      }
    }
  }
  return 0;
}
