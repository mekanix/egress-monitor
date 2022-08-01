PREFIX?=	/usr/local
LOCALBASE?=	/usr/local
BINDIR=         ${PREFIX}/sbin
MANDIR=         ${PREFIX}/man/man
LIBDIR=         ${PREFIX}/lib

PROG=		egress-monitor
SRCS=		egress-monitor.c

.include <bsd.prog.mk>
